import asyncio
import logging
import socket
try:
    import uvloop
    asyncio.set_event_loop(uvloop.new_event_loop())
except ImportError:
    pass

HOST = "0.0.0.0"
PORT = 9001
USERNAME = 'proxy'
PASSWORD = 'proxy'
CONNECT_TIMEOUT = 30
AUTH_REQUIRE = True
UDP_IP = "0.0.0.0"

def auth(username, password):   #修改这个实现自定义验证
    return username==USERNAME and password==PASSWORD

def cancel(future):
    if not future.done():
        future.cancel()

class ServerProtocol(asyncio.Protocol):
    def __init__(self, loop):
        self.loop = loop
        self.connected = False
        self.version = None
        self.remoteclient = None
        self.task_list = []
        self.authed = False

    def connection_made(self, transport):
        self.transport = transport

    def write(self, data):
        self.transport.write(data)

    def data_received(self,data):
        if self.connected:   #代理连接已经建立，大量的数据传输都在已建立连接的情况下，所以这个判断写最前面
            if self.remoteclient:
                logging.debug("Send to remote:", data)
                self.remoteclient.write(data)     #直接发送咯
        elif not self.version:   #第一条数据，还没确定版本
            if data.startswith(b'\x04'):
                self.version = 4
                task = asyncio.ensure_future(self.deal_connect_v4(data))  #sock4代理协程
                self.task_list.append(task)
            elif data.startswith(b'\x05'):
                self.version = 5
                if data in (b'\x05\x02\x00\x02',b'\x05\x01\x00',b'\x05\x01\x02'):  #代理请求信息，这里只支持这几种情况
                    if AUTH_REQUIRE:
                        self.write(b'\x05\x02') #返回b'\x05\x02'请求验证，返回b'\x05\x00'允许代理
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
    def __init__(self,server_protocol):  #参数是代理服务器的协议的实例
        self.server_protocol = server_protocol
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        logging.debug("Get from remote:",data)
        self.server_protocol.write(data)  #直接转发

    def connection_lost(self, exc):
        self.server_protocol.close()

    def write(self,data):
        self.transport.write(data)

    def close(self):
        if not self.transport.is_closing():
            self.transport.close()

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    coro = loop.create_server(lambda :ServerProtocol(loop), HOST, PORT)
    loop.run_until_complete(coro)
    print("Listen on %s:%s ...."%(HOST, PORT))
    try:
        loop.run_forever()
    finally:
        loop.close()
