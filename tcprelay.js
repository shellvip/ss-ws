const net = require('net');
const path = require('path');
const WebSocket = require('ws');
const Encryptor = require('shadowsocks/lib/shadowsocks/encrypt').Encryptor;
const WSErrorCode = require('ws/lib/ErrorCodes');

const MAX_CONNECTIONS = 50000;

const TCP_RELAY_TYPE_LOCAL = 1;
const TCP_RELAY_TYPE_SERVER = 2;

const ADDRESS_TYPE_IPV4 = 0x01;
const ADDRESS_TYPE_DOMAIN_NAME = 0x03;
const ADDRESS_TYPE_IPV6 = 0x04;
const ADDRESS_TYPE = {
    1: 'IPV4',
    3: 'DOMAIN_NAME',
    4: 'IPV6'
};

const VERSION = 0x05;

const METHOD_NO_AUTHENTICATION_REQUIRED = 0x00;
const METHOD_GSSAPI = 0x01;
const METHOD_USERNAME_PASSWORD = 0x02;
const METHOD_NO_ACCEPTABLE_METHODS = 0xff;

const CMD_CONNECT = 0x01;
const CMD_BIND = 0x02;
const CMD_UDP_ASSOCIATE = 0x03;
const CMD = {
    1: 'CONNECT',
    2: 'BIND',
    3: 'UDP_ASSOCIATE'
};

const REPLIE_SUCCEEDED = 0x00;
const REPLIE_GENERAL_SOCKS_SERVER_FAILURE = 0x01;
const REPLIE_CONNECTION_NOT_ALLOWED_BY_RULESET = 0x02;
const REPLIE_NETWORK_UNREACHABLE = 0x03;
const REPLIE_HOST_UNREACHABLE = 0x04;
const REPLIE_CONNECTION_REFUSED = 0x05;
const REPLIE_TTL_EXPIRED = 0x06;
const REPLIE_COMMAND_NOT_SUPPORTED = 0x07;
const REPLIE_ADDRESS_TYPE_NOT_SUPPORTED = 0x08;

const STAGE_INIT = 0;
const STAGE_ADDR = 1;
const STAGE_UDP_ASSOC = 2;
const STAGE_DNS = 3;
const STAGE_CONNECTING = 4;
const STAGE_STREAM = 5;
const STAGE_DESTROYED = -1;

const STAGE = {
    [-1]: 'STAGE_DESTROYED',
    0: 'STAGE_INIT',
    1: 'STAGE_ADDR',
    2: 'STAGE_UDP_ASSOC',
    3: 'STAGE_DNS',
    4: 'STAGE_CONNECTING',
    5: 'STAGE_STREAM'
};

const SERVER_STATUS_INIT = 0;
const SERVER_STATUS_RUNNING = 1;
const SERVER_STATUS_STOPPED = 2;

var globalConnectionId = 1;
var connections = {};

function parseAddressHeader(data, offset) {
    var addressType = data.readUInt8(offset);
    var headerLen, dstAddr, dstPort, dstAddrLen;
    //domain name
    if (addressType == ADDRESS_TYPE_DOMAIN_NAME) {
        dstAddrLen = data.readUInt8(offset + 1);
        dstAddr = data.slice(offset + 2, offset + 2 + dstAddrLen).toString();
        dstPort = data.readUInt16BE(offset + 2 + dstAddrLen);
        headerLen = 4 + dstAddrLen;
    }
    //ipv4
    else if (addressType == ADDRESS_TYPE_IPV4) {
        dstAddr = data.slice(offset + 1, offset + 5).join('.').toString();
        dstPort = data.readUInt16BE(offset + 5);
        headerLen = 7;
    } else {
        return false;
    }
    return {
        addressType: addressType,
        headerLen: headerLen,
        dstAddr: dstAddr,
        dstPort: dstPort
    };
}

module.exports = class TcpRelay {
    constructor(config, isLocal) {
        this.isLocal = isLocal;
        this.server = null;
        this.status = SERVER_STATUS_INIT;
        this.config = require('./config.json');
        if (config) {
            this.config = Object.assign(this.config, config);
        }
        this.serverName = null;
    }

    getStatus() {
        return this.status;
    }

    initServer() {
        return new Promise(function (resolve, reject) {
            var config = this.config;
            var port = this.isLocal ? config.localPort : config.serverPort;
            var address = this.isLocal ? config.localAddress : config.serverAddress;
            var server;

            if (this.isLocal) {
                server = this.server = net.createServer({
                    allowHalfOpen: true,
                });
                server.maxConnections = MAX_CONNECTIONS;
                server.on('connection', function (connection) {
                    return this.handleConnectionByLocal(connection);
                });
                server.on('close', function () {
                    this.status = SERVER_STATUS_STOPPED;
                });
                server.listen(port, address);
            } else {
                server = this.server = new WebSocket.Server({
                    host: address,
                    port: port,
                    perMessageDeflate: false
                });
                server.on('connection', function (connection) {
                    return this.handleConnectionByServer(connection);
                });
            }
            server.on('error', function (error) {
                this.status = SERVER_STATUS_STOPPED;
                reject(error);
            });
            server.on('listening', function () {
                this.status = SERVER_STATUS_RUNNING;
                resolve();
            });
        });
    }

    handleConnectionByServer(connection) {
        var config = this.config;
        var method = config.method;
        var password = config.password;
        var serverAddress = config.serverAddress;
        var serverPort = config.serverPort;

        var encryptor = new Encryptor(password, method);

        var stage = STAGE_INIT;
        var connectionId = (globalConnectionId++) % MAX_CONNECTIONS;
        var targetConnection, addressHeader;

        var dataCache = [];

        connections[connectionId] = connection;
        connection.on('message', function (data) {
            data = encryptor.decrypt(data);

            switch (stage) {

                case STAGE_INIT:
                    if (data.length < 7) {
                        stage = STAGE_DESTROYED;
                        return connection.close();
                    }
                    addressHeader = parseAddressHeader(data, 0);
                    if (!addressHeader) {
                        stage = STAGE_DESTROYED;
                        return connection.close();
                    }

                    stage = STAGE_CONNECTING;

                    targetConnection = net.createConnection({
                        port: addressHeader.dstPort,
                        host: addressHeader.dstAddr,
                        allowHalfOpen: true
                    }, function () {

                        dataCache = Buffer.concat(dataCache);
                        targetConnection.write(dataCache, function () {
                            dataCache = null;
                        });
                        stage = STAGE_STREAM;
                    });

                    targetConnection.on('data', function (data) {
                        if (connection.readyState == WebSocket.OPEN) {
                            connection.send(encryptor.encrypt(data), {
                                binary: true
                            }, function () {
                            });
                        }
                    });
                    targetConnection.on('end', function () {
                        stage = STAGE_DESTROYED;
                        connection.close();
                    });
                    targetConnection.on('close', function (hadError) {
                        stage = STAGE_DESTROYED;
                        connection.close();
                    });
                    targetConnection.on('error', function (error) {
                        stage = STAGE_DESTROYED;
                        targetConnection.destroy();
                        connection.close();
                    });

                    if (data.length > addressHeader.headerLen) {
                        dataCache.push(data.slice(addressHeader.headerLen));
                    }
                    break;

                case STAGE_CONNECTING:
                    dataCache.push(data);
                    break;

                case STAGE_STREAM:
                    targetConnection.write(data, function () {
                    });
                    break;
            }
        });
        connection.on('close', function (code, reason) {
            connections[connectionId] = null;
            targetConnection && targetConnection.destroy();
        });
        connection.on('error', function (error) {
            connection.terminate();
            connections[connectionId] = null;
            targetConnection && targetConnection.end();
        });
    }

    handleConnectionByLocal(connection) {
        var config = this.config;
        var method = config.method;
        var password = config.password;
        var serverAddress = config.serverAddress;
        var serverPort = config.serverPort;

        var encryptor = new Encryptor(password, method);

        var stage = STAGE_INIT;
        var connectionId = (globalConnectionId++) % MAX_CONNECTIONS;
        var serverConnection, cmd, addressHeader;

        var canWriteToLocalConnection = true;
        var dataCache = [];

        connections[connectionId] = connection;
        connection.setKeepAlive(false);
        connection.on('data', function (data) {
            switch (stage) {

                case STAGE_INIT:
                    if (data.length < 3 || data.readUInt8(0) != 5) {
                        stage = STAGE_DESTROYED;
                        return connection.end();
                    }
                    connection.write("\x05\x00");
                    stage = STAGE_ADDR;
                    break;

                case STAGE_ADDR:
                    if (data.length < 10 || data.readUInt8(0) != 5) {
                        stage = STAGE_DESTROYED;
                        return connection.end();
                    }
                    cmd = data.readUInt8(1);
                    addressHeader = parseAddressHeader(data, 3);
                    if (!addressHeader) {
                        stage = STAGE_DESTROYED;
                        return connection.end();
                    }

                    //only supports connect cmd
                    if (cmd != CMD_CONNECT) {
                        stage = STAGE_DESTROYED;
                        return connection.end("\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00");
                    }

                    connection.write("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00");

                    stage = STAGE_CONNECTING;

                    serverConnection = new WebSocket('ws://' + serverAddress + ':' + serverPort, {
                        perMessageDeflate: false
                    });
                    serverConnection.on('open', function () {
                        serverConnection.send(encryptor.encrypt(data.slice(3)), function () {
                            stage = STAGE_STREAM;
                            dataCache = Buffer.concat(dataCache);
                            serverConnection.send(encryptor.encrypt(dataCache), {
                                binary: true
                            }, function () {
                                dataCache = null;
                            });
                        });
                    });
                    serverConnection.on('message', function (data) {
                        canWriteToLocalConnection && connection.write(encryptor.decrypt(data), function () {
                        });
                    });
                    serverConnection.on('error', function (error) {
                        stage = STAGE_DESTROYED;
                        connection.end();
                    });
                    serverConnection.on('close', function (code, reason) {
                        stage = STAGE_DESTROYED;
                        connection.end();
                    });

                    if (data.length > addressHeader.headerLen + 3) {
                        dataCache.push(data.slice(addressHeader.headerLen + 3));
                    }
                    break;

                case STAGE_CONNECTING:
                    dataCache.push(data);
                    break;

                case STAGE_STREAM:
                    canWriteToLocalConnection && serverConnection.send(encryptor.encrypt(data), {
                        binary: true
                    }, function () {
                    });
                    break;
            }
        });
        connection.on('end', function () {
            stage = STAGE_DESTROYED;
        });
        connection.on('close', function (hadError) {
            stage = STAGE_DESTROYED;
            canWriteToLocalConnection = false;
            connections[connectionId] = null;
            serverConnection && serverConnection.terminate();
        });
        connection.on('error', function (error) {
            stage = STAGE_DESTROYED;
            connection.destroy();
            canWriteToLocalConnection = false;
            connections[connectionId] = null;
            serverConnection && serverConnection.close();
        });
    }
    stop() {
        var connId = null;
        return new Promise(function (resolve, reject) {
            if (this.server) {
                this.server.close(function () {
                    resolve();
                });

                for (connId in connections) {
                    if (connections[connId]) {
                        this.isLocal ? connections[connId].destroy() : connections[connId].terminate();
                    }
                }

            } else {
                resolve();
            }
        });
    }
}
