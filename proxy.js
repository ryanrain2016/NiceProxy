var https = require('https');
var httpProxy = require('http-proxy');  //npm install http-proxy --save
var net = require('net');
var fs = require('fs');
var tls = require('tls');
const key = fs.readFileSync('key.pem');
const cert = fs.readFileSync('cert.pem');
var proxy = httpProxy.createProxyServer({});
process.on('uncaughtException', (e)=>{
    console.log(e.stack);
});
const options = {
    key: key,
    cert: cert,
    rejectUnauthorized:false,
    secureOptions:tls.SSL_OP_NO_SSLv2 | tls.SSL_OP_NO_SSLv3
}
var server = https.createServer(options, function(req, res) {
    var us = req.url.split('/');
    proxy.web(req, res, {                     //http代理
        target: us[0]+'//'+us[2]
    });
});
server.on('connect', (req, cltSocket, head)=>{    //https/websocket代理
    var hp = req.url.split(':')
    try{
        var srvSocket = net.connect(hp[1], hp[0], () => {
            cltSocket.write('HTTP/1.1 200 Connection Established\r\n' +
                            'Proxy-agent: NiceProxy\r\n' +
                            '\r\n');
            srvSocket.write(head);
            srvSocket.pipe(cltSocket);
            cltSocket.pipe(srvSocket);
        });
    } catch(e) {
        cltSocket.close();
    }
});

server.listen(5050);