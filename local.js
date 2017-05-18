const TcpRelay = require('./tcprelay');
const local = require('commander');

local.version('1.1.8')
    .option('-m --method <method>', 'encryption method')
    .option('-k --password <password>', 'password')
    .option('-s --server-address <address>', 'server address')
    .option('-p --server-port <port>', 'server port, default: 8088')
    .option('-b --local-address <address>', 'local binding address, default: 127.0.0.1')
    .option('-l --local-port <port>', 'local port, default: 1080')
    .parse(process.argv);

var relay = new TcpRelay({
    localAddress: local.localAddress || '127.0.0.1',
    localPort: local.localPort || 1080,
    serverAddress: local.serverAddress || '127.0.0.1',
    serverPort: local.serverPort || 8088,
    password: local.password || 'shadowsocks-over-websocket',
    method: local.method || 'rc4-md5'
}, true);

relay.initServer().then(()=>{
    console.log('Init server ok.');
}, ()=>{
    console.log('Init server error.');
});
