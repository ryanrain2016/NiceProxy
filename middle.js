var net = require('net');
var tls = require('tls');
var fs = require('fs');

const HOST = '127.0.0.1';
const PORT = 5050;

var LHOST = '127.0.0.1';
var LPORT = 12346;
var cert = fs.readFileSync('cert.pem');
//process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
net.createServer(function(sock){
    var client = tls.connect({
        host:HOST,
        port:PORT,
        cert:cert,
        servername:'NiceProxy.org',
        rejectUnauthorized:false,
        secureOptions:tls.SSL_OP_NO_SSLv2 | tls.SSL_OP_NO_SSLv3
    }, function(){});
    client.on('data', function(data) {
        sock.write(data);
    });

    // 为客户端添加“close”事件处理函数
    client.on('close', function() {
        sock.destroy();
    });
    //client.on('error',(e)=>{console.log(e)});

    sock.on('data', function(data){
        client.write(data);
    });
    sock.on('close', function(data) {
        client.destroy()
    });
}).listen(LPORT, LHOST);

console.log('Server listening on ' + LHOST +':'+ LPORT);
