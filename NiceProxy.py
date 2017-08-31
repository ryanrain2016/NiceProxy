#!/usr/bin/env python
import asyncio
import logging
import socket
import ssl
import sys, os
HTTP_PROXY_ENABLE = True
try:
    from httptools import HttpRequestParser, parse_url
    from httptools.parser.errors import HttpParserError,HttpParserUpgrade
except ImportError:
    HTTP_PROXY_ENABLE = False
try:
    import uvloop
    asyncio.set_event_loop(uvloop.new_event_loop())
except ImportError:
    pass
ISWIN32 = sys.platform == 'win32'
LOG_LEVEL = logging.WARN
HOST = "0.0.0.0"       #本地监听IP
PORT = 9001            #本地监听端口
USERNAME = 'proxy'
PASSWORD = 'proxy'
CONNECT_TIMEOUT = 30   #连接时超时时间
AUTH_REQUIRE = False    #sock5是否需要认证
UDP_IP = "0.0.0.0"      #sock5 UDP的端口
SSL_ENABLE = False
#ssl自签名证书可以通过下面命令生成
#openssl req -new -x509 -days 3650 -nodes -out cert.pem -keyout key.pem
if ISWIN32:
    SSL_CERT_FILE = 'keys/cert.pem'
    SSL_KEY_FILE = 'keys/key.pem'
    LOG_FILE = 'NiceProxy.log'
else:
    import pwd
    USER = "NiceProxy"
    SSL_CERT_FILE = '/usr/app/NiceProxy/keys/cert.pem'
    SSL_KEY_FILE = '/usr/app/NiceProxy/keys/key.pem'
    LOG_FILE = '/var/log/NiceProxy/NiceProxy.log'
    PID_FILE = '/var/run/NiceProxy/NiceProxy.pid'

logging.basicConfig(level=LOG_LEVEL,
    format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
    datefmt='%a, %d %b %Y %H:%M:%S',
    filename=LOG_FILE,
    filemode='a')

def auth(username, password):   #修改这个实现自定义验证
    return username==USERNAME and password==PASSWORD

def cancel(future):
    if not future.done():
        future.cancel()

class ServerProtocol(asyncio.Protocol):
    def __init__(self, loop = None):
        self.loop = loop or asyncio.get_event_loop()
        self.connected = False
        self.version = None
        self.remoteclient = None
        self.task_list = []
        self.authed = False
        #下面是http代理需要用到的
        self.is_http = False
        self.parser = None
        self.url = None
        self.buffer = asyncio.Queue()
        self.remotes = {}
        self.is_https_proxying = False
        self.headers = []
        self.responsing = False
        self.body = []
        self.should_keep_alive = False


    def connection_made(self, transport):
        self.transport = transport

    def write(self, data):
        if self.is_http:
            if self.responsing:
                try:
                    self.transport.write(data)
                except:
                    self.close()
        else:
            self.transport.write(data)

    def on_url(self, url):
        self.url = url

    def on_header(self, name, value):
        if name != b'Proxy-Connection':
            self.headers.append(b'%s: %s\r\n'%(name, value))
        else:
            self.headers.append(b'Connection: %s\r\n'%value)
            self.should_keep_alive = True

    def on_headers_complete(self):
        self.headers.append(b'\r\n')
        method = self.parser.get_method()
        version = self.parser.get_http_version()
        if method != b'CONNECT':
            url = parse_url(self.url)
            host = url.host.decode()
            port = url.port or (443 if url.schema==b'https' else 80)
            full_path = url.path or b'/'
            if url.query is not None:
                full_path = full_path + b'?' + url.query
            if url.fragment is not None:
                full_path = full_path + b'#' + fragment
            firstline = b'%s %s HTTP/%s\r\n'%(method, full_path, version.encode())
            self.headers.insert(0, firstline)
            self.buffer.put_nowait(b''.join(self.headers))
            task = asyncio.ensure_future(self.sendTo(host, port, self.buffer))
        else:
            task = asyncio.ensure_future(self.proxy_https(self.url.decode()))
        self.task_list.append(task)


    async def proxy_https(self, addr):
        host, port = addr.split(':', 1)
        port = int(port)
        task = self.loop.create_connection(lambda:RemoteClientProtocol(self,addr), host, port)
        future = asyncio.ensure_future(task)
        self.loop.call_later(30, future.cancel)
        try:
            _, self.remoteclient = await future
        except:
            self.write(b'HTTP/1.1 502 Bad Gateway\r\nProxy-Agent: NiceProxy\r\n\r\n')
            self.close()
            return
        else:
            self.is_https_proxying = True
            self.write(b'HTTP/1.1 200 Connection Established\r\nProxy-Agent: NiceProxy\r\n\r\n')

    def on_body(self, body):
        self.body.append(body)

    def on_message_complete(self):
        self.buffer.put_nowait(b''.join(self.body))
        self.buffer.put_nowait(None)
        self.cleanup()

    def deal_proxy_http(self, data):
        if self.is_https_proxying:
            self.remoteclient.write(data)
            return
        self.responsing = False
        if self.parser is None:
            self.headers = []
            self.parser = HttpRequestParser(self)
        try:
            self.parser.feed_data(data)
        except HttpParserError:
            self.close()
        except HttpParserUpgrade:
            pass      #解析ssl代理的握手消息会报这个错，不过无所谓，on_headers_complete回调已执行

    async def sendTo(self, host, port, queue):
        addr = "%s:%s"%(host, port)
        remote = self.remotes.get(addr, None)
        if remote is None:
            task = self.loop.create_connection(lambda:RemoteClientProtocol(self, addr), host, port)
            future = asyncio.ensure_future(task)
            self.loop.call_later(30, future.cancel)
            try:
                _, client_protocol = await future
            except:
                self.write(b'HTTP/1.1 502 Bad Gateway\r\nProxy-Agent: NiceProxy\r\n\r\n')
                self.close()
                return
            remote = self.remotes[addr] = client_protocol
        while True:
            try:
                line = await queue.get()
            except:
                break
            if line is not None:
                if line:
                    remote.write(line)
                queue.task_done()
            else:
                queue.task_done()
                break

    def cleanup(self):
        self.parser = None
        self.buffer = asyncio.Queue()
        self.url = None
        self.headers = []
        self.body = []
        self.responsing = True

    def data_received(self,data):
        if self.connected:   #代理连接已经建立，大量的数据传输都在已建立连接的情况下，所以这个判断写最前面
            if self.remoteclient:
                logging.debug("Send to remote:", data)
                self.remoteclient.write(data)     #直接发送咯
        elif self.is_http:
            self.deal_proxy_http(data)
            return
        elif not self.version and data.startswith(b'\x04'):   #第一条数据，还没确定版本
            self.version = 4
            task = asyncio.ensure_future(self.deal_connect_v4(data))  #sock4代理协程
            self.task_list.append(task)
        elif not self.version and data.startswith(b'\x05'):
            self.version = 5
            options = data[2:2+data[1]]
            if AUTH_REQUIRE:
                if b'\x02' in options:
                    self.write(b'\x05\x02') #返回b'\x05\x02'请求验证，返回b'\x05\x00'允许代理
                else:
                    self.close()
            else:
                self.authed = True
                self.write(b'\x05\x00')
        elif self.version==5:   
            if data.startswith(b'\x01'): #Sock5 的代理请求后的认证信息
                u_len = data[1]
                username = data[2:2+u_len].decode()
                p_len = data[2+u_len]
                password = data[3+u_len:3+u_len+p_len].decode()
                if auth(username,password):  #获取到的账号密码验证
                    self.authed = True
                    self.write(b'\x05\x00')
                else:
                    self.close()
            elif not self.authed:   #没有认证,关闭连接
                self.close()
                return
            elif data.startswith(b'\x05\x01'):   #TCP代理
                task = asyncio.ensure_future(self.deal_connect_v5(data))
                self.task_list.append(task)
            elif data.startswith(b'\x05\x03'):   #UDP代理
                task = asyncio.ensure_future(self.deal_udp_v5(data))
                self.task_list.append(task)
            else:
                self.close()
        elif HTTP_PROXY_ENABLE:
            self.is_http = True
            self.deal_proxy_http(data)

    def connection_lost(self, exc):
        self.close()

    def close(self):
        for task in self.task_list:   #取消所有task
            cancel(task)
        self.task_list = []
        if not self.transport.is_closing():  #关闭客户端连接
            self.transport.close()
        if self.remoteclient:
            self.remoteclient.close()   #关闭远程连接
        for remote in self.remotes.values():
            remote.close()
        self.parser = None

    async def deal_connect_v4(self,data):
        ip = socket.inet_ntoa(data[4:8])
        if ip == '0.0.0.1':
            ip = data[9:-1].decode()
        port = data[2:4]
        port = (port[0]<<8)|port[1]
        await self.connect_remote(ip,port) #解析出远程地址端口，建立连接

    async def deal_connect_v5(self,data):
        ip_or_domain = data[3]    #  b'\x03'为域名 b'\x01'为IP
        if ip_or_domain == 0x01:
            addr = socket.inet_ntoa(data[4:8])
            port = data[8:10]
        elif ip_or_domain == 0x03:
            d_len = data[4]
            addr = data[5:5+d_len].decode()
            port = data[5+d_len:7+d_len]
        else:
            return
        port = (port[0]<<8)|port[1]
        await self.connect_remote(addr,port)#解析出远程地址端口，建立连接

    async def connect_remote(self,ip,port):
        logging.debug("Got Sock%d proxy request!connecting to %s:%s"%(self.version, ip, port))
        connect_coro = self.loop.create_connection(
                lambda:RemoteClientProtocol(self),
                host=ip,
                port=port
            )  #远程连接的协程
        connect_future = asyncio.ensure_future(connect_coro)
        self.loop.call_later(CONNECT_TIMEOUT, cancel, connect_future)  #超时的话就取消连接协程
        try:
            _, self.remoteclient = await connect_future
        except:
            self.close()  #超时或者出错
        else:
            #建立完连接， 返回响应
            if self.version == 4:
                self.write(b'\x00\x5a\x00\x00\x00\x00\x00\x00')
            elif self.version == 5:
                self.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            self.connected = True #设置连接完成标识

    async def deal_udp_v5(self, data):
        addr = socket.inet_ntoa(data[4:8])
        port = data[8:10]
        port = (port[0]<<8)|port[1]
        req_addr = (addr, port)   #解析udp请求中的地址
        #建立udp服务器，这里没有定义端口，由系统分配
        transport, _ = await self.loop.create_datagram_endpoint(
            lambda:RemoteClientUDPProtocol(req_addr), local_addr=(UDP_IP, 0))
        addr = transport._sock.getsockname()  #得到udp服务器的地址：(ip，port)
        ip = socket.inet_aton(addr[0]) #ip 转bytes
        port = bytes([(port >> 8)&0xff,port & 0xff])  #端口转bytes
        self.write(b'\x05\x00\x00\x01'+ip+port)  #返回响应

class RemoteClientUDPProtocol(asyncio.Protocol):  #udp代理时，udp服务器协议
    def __init__(self, addr):
        self.req_addr = addr 
        self.addr_list = {}

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if addr == self.req_addr:  #客户端发送的数据
            if not data.startswith(b'\x00\x00\x00'):
                return
            ip_or_domain = data[3]
            if ip_or_domain == 0x01:
                addr = socket.inet_ntoa(data[4:8])
                port = data[8:10]
                head_len = 10
            elif ip_or_domain == 0x03:
                d_len = data[4]
                addr = data[5:5+d_len].decode()
                port = data[5+d_len:7+d_len]
                head_len = 7+d_len
            port = (port[0]<<8)|port[1]  #解析出地址，端口
            self.transport.sendto(data[head_len:],(addr,port)) #发送原始数据包
            if (addr, port) not in self.addr_list:   #记录远程地址,顺便记录前缀,免得每次重新计算
                self.addr_list[(addr, port)] = data[:head_len]
                # TODO: 这里需要将domain转成IP存，因为这里的参数addr中的host，只会是ip
        elif addr in self.addr_list:  #远端地址返回的数据，返回给客户端
            prefix = self.addr_list[addr]
            self.transport.sendto(prefix+data, self.req_addr)

class RemoteClientProtocol(asyncio.Protocol):  #与远端地址建立连接的协议
    def __init__(self,server_protocol, addr=None):  #参数是代理服务器的协议的实例
        self.server_protocol = server_protocol
        self.transport = None
        self.addr = addr

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        logging.debug("Get from remote:",data)
        self.server_protocol.write(data)  #直接转发

    def connection_lost(self, exc):
        if self.server_protocol:
            self.server_protocol.close()
        if self.addr in self.server_protocol.remotes:
            del self.server_protocol.remotes[self.addr]

    def write(self,data):
        self.transport.write(data)

    def close(self):
        if not self.transport.is_closing():
            self.transport.close()

def main():
    loop = asyncio.get_event_loop()
    context = None
    if SSL_ENABLE:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=SSL_CERT_FILE, keyfile=SSL_KEY_FILE)
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
    coro = loop.create_server(lambda :ServerProtocol(loop), HOST, PORT, ssl=context)
    loop.run_until_complete(coro)
    print("Listen on %s:%s ...."%(HOST, PORT))
    try:
        loop.run_forever()
    finally:
        loop.close()

if __name__ == '__main__':
    if ISWIN32:
        main()
    else:
        try:
            user = pwd.getpwnam(USER)
            uid = user.pw_uid
        except:
            logging.WARN("User: [%s] not Found! Using root is insecure!",USER)
            uid = pwd.getpwnam('root').pw_uid
        pid = os.fork()
        if(pid):sys.exit(0)
        os.setsid()
        os.chdir("/")
        os.umask(0)
        pid=os.fork()
        if(pid):
            try:
                with open(PID_FILE, 'w') as f:
                    f.write(str(pid))
            except:
                logging.error("Can't open file %s",PID_FILE)
                sys.exit(-1)
            else:
                sys.exit(0)
        os.setuid(uid)
        os.setsid()
        os.chdir("/")
        os.umask(0)
        main()

