const net = require('net');
const path = require('path');
const http = require('http');
const WebSocket = require('ws');
const Encryptor = require('shadowsocks/lib/shadowsocks/encrypt').Encryptor;

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
    }

    initServer() {
        var self = this;
        return new Promise(function (resolve, reject) {
            var config = self.config;
            var port = self.isLocal ? config.localPort : config.serverPort;
            var address = self.isLocal ? config.localAddress : config.serverAddress;
            var server;

            if (self.isLocal) {
                server = self.server = net.createServer();
                server.on('connection', function (connection) {
                    return self.handleConnectionByLocal(connection);
                });
            } else {
                server = self.server = http.createServer((req, res) => {
                    res.writeHead(200, { 'Content-Type': 'text/plain' });
                    return res.end("Hello world.");
                });
                var wss = new WebSocket.Server({ server });
                wss.on('connection', function (ws) {
                    return self.handleConnectionByServer(ws);
                });
            }
            server.listen(port, address, () => {
                self.status = SERVER_STATUS_RUNNING;
                resolve();
            });
            server.on('error', function (error) {
                self.status = SERVER_STATUS_STOPPED;
                reject(error);
            });
        });
    }

    handleConnectionByServer(ws) {
        var config = this.config;
        var method = config.method;
        var password = config.password;
        var serverAddress = config.serverAddress;
        var serverPort = config.serverPort;

        console.log("server connected");

        var encryptor = new Encryptor(password, method);

        var stage = STAGE_INIT;
        var remote, addressHeader;

        var dataCache = [];

        ws.on('message', function (data, flags) {
            data = encryptor.decrypt(data);
            switch (stage) {
                case STAGE_INIT:
                    try {
                        if (data.length < 7) {
                            stage = STAGE_DESTROYED;
                            return ws.close();
                        }
                        addressHeader = parseAddressHeader(data, 0);
                        if (!addressHeader) {
                            stage = STAGE_DESTROYED;
                            return ws.close();
                        }

                        stage = STAGE_CONNECTING;

                        remote = net.connect(addressHeader.dstPort, addressHeader.dstAddr, () => {
                            console.log(`connecting ${addressHeader.dstAddr}`);
                            dataCache = Buffer.concat(dataCache);
                            remote.write(dataCache, () => {
                                dataCache = null;
                            });
                            stage = STAGE_STREAM;
                        });

                        remote.on('data', function (data) {
                            if (ws.readyState == WebSocket.OPEN) {
                                ws.send(encryptor.encrypt(data), {
                                    binary: true
                                });
                                if (ws.bufferedAmount > 0) {
                                    remote.pause();
                                }
                            }
                        });
                        remote.on('end', function () {
                            stage = STAGE_DESTROYED;
                            ws.close();
                            console.log("remote disconnected");
                        });
                        remote.on('close', function (hadError) {
                            stage = STAGE_DESTROYED;
                            ws.close();
                        });
                        remote.on("drain", function () {
                            ws._socket.resume();
                        });
                        remote.on('error', function (error) {
                            stage = STAGE_DESTROYED;
                            remote.destroy();
                            ws.terminate();
                        });
                        remote.setTimeout(Math.floor(600 * 1000), () => {
                            console.log("remote timeout");
                            remote.destroy();
                            ws.close();
                        });

                        if (data.length > addressHeader.headerLen) {
                            dataCache.push(data.slice(addressHeader.headerLen));
                        }
                    } catch (error) {
                        console.warn(error);
                        if (remote) {
                            remote.destroy();
                        }
                        ws.close();
                    }
                    break;

                case STAGE_CONNECTING:
                    dataCache.push(data);
                    break;

                case STAGE_STREAM:
                    if (!remote.write(data)) {
                        ws._socket.pause();
                    }
                    break;
            }
        });
        ws.on('close', function (code, reason) {
            console.log("server disconnected");
            if (remote) {
                return remote.destroy();
            }
        });

        ws.on('error', function (error) {
            console.warn("server: " + e);
            if (remote) {
                return remote.destroy();
            }
        });
    }

    handleConnectionByLocal(connection) {
        var config = this.config;
        var method = config.method;
        var password = config.password;
        var serverAddress = config.serverAddress;
        var serverPort = config.serverPort;

        console.log("local connected");

        var encryptor = new Encryptor(password, method);

        var stage = STAGE_INIT;
        var ws, cmd, addressHeader, ping;

        var canWriteToLocalConnection = true;
        var dataCache = [];

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
                    try {
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

                        ws = new WebSocket('ws://' + serverAddress + ':' + serverPort, {
                            protocol: "binary"
                        });
                        ws.on('open', function () {
                            ws._socket.on("error", function (e) {
                                connection.destroy();
                            });
                            ws.send(encryptor.encrypt(data.slice(3)), function () {
                                stage = STAGE_STREAM;
                                dataCache = Buffer.concat(dataCache);
                                ws.send(encryptor.encrypt(dataCache), {
                                    binary: true
                                }, function () {
                                    dataCache = null;
                                });
                            });
                            ping = setInterval(function () {
                                return ws.ping("", null, true);
                            }, 50 * 1000);
                            ws._socket.on("drain", function () {
                                return connection.resume();
                            });
                        });
                        ws.on('message', function (data, flags) {
                            if (!connection.write(encryptor.decrypt(data))) {
                                return ws._socket.pause();
                            }
                        });
                        ws.on('close', function (code, reason) {
                            stage = STAGE_DESTROYED;
                            clearInterval(ping);
                            console.log("remote disconnected");
                            connection.destroy();
                        });
                        ws.on('error', function (error) {
                            stage = STAGE_DESTROYED;
                            connection.destroy();
                        });

                        if (data.length > addressHeader.headerLen + 3) {
                            dataCache.push(data.slice(addressHeader.headerLen + 3));
                        }
                    } catch (error) {
                        console.log(error);
                        return connection.destroy();
                    }

                    break;

                case STAGE_CONNECTING:
                    dataCache.push(data);
                    break;

                case STAGE_STREAM:
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send(encryptor.encrypt(data), {
                            binary: true
                        });
                        if (ws.bufferedAmount > 0) {
                            connection.pause();
                        }
                    }
                    break;
            }
        });
        connection.on('end', function () {
            stage = STAGE_DESTROYED;
            console.log("local disconnected");
            if (ws) {
                ws.terminate();
            }
        });
        connection.on('close', function (hadError) {
            stage = STAGE_DESTROYED;
            console.log("local disconnected");
            if (ws) {
                ws.terminate();
            }
        });
        connection.on('error', function (error) {
            stage = STAGE_DESTROYED;
            connection.destroy();
            if (ws) {
                ws.terminate();
            }
        });
        connection.on("drain", function () {
            if (ws && ws._socket) {
                ws._socket.resume();
            }
        });
        connection.setTimeout(Math.floor(600 * 1000), function () {
            console.log("local timeout");
            connection.destroy();
            if (ws) {
                return ws.terminate();
            }
        });
    }

}
