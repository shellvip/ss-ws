const TcpRelay = require('./tcprelay');
const server = require('commander');

server.version('1.1.8')
    .option('-m --method <method>', 'encryption method, default: aes-256-cfb')
    .option('-k --password <password>', 'password')
    .option('-s --server-address <address>', 'server address')
    .option('-p --server-port <port>', 'server port, default: 8088')
    .parse(process.argv);

var relay = new TcpRelay({
    serverAddress: server.serverAddress || '127.0.0.1',
    serverPort: server.serverPort || 8088,
    password: server.password || 'shadowsocks-over-websocket',
    method: server.method || 'aes-256-cfb'
}, false);

relay.initServer().then(()=>{
    console.log('Init server ok.');
}, ()=>{
    console.log('Init server error.');
});
