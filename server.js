const TcpRelay = require('./tcprelay');
const server = require('commander');

server.version('1.1.8')
    .option('-m --method <method>', 'encryption method')
    .option('-k --password <password>', 'password')
    .option('-s --server-address <address>', 'server address')
    .option('-p --server-port <port>', 'server port, default: 8088')
    .parse(process.argv);

var relay = new TcpRelay({
    serverAddress: server.serverAddress || '0.0.0.0',
    serverPort: process.env.PORT || server.serverPort || 8088,
    password: server.password || 'shadowsocks-over-websocket',
    method: server.method || 'rc4-md5'
}, false);

relay.initServer().then(()=>{
    console.log('Init server ok.');
}, ()=>{
    console.log('Init server error.');
});
