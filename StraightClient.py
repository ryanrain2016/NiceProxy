import asyncio 
try:
    import uvloop
    asyncio.set_event_loop(uvloop.new_event_loop())
except ImportError:
    pass
import ssl
REMOTE_HOSTNAME = 'remote-addr.com'   #若启用ssl,该值为建立ssl连接时验证服务证书签名使用的hostname
REMOTE_HOST = 'remote-addr.com'  #转发的地址
REMOTE_PORT = '8080'               #转发的端口

HOST = '0.0.0.0'   #本地监听的ip
PORT = 1080   #本地监听端口

CONNECT_TIMEOUT = 30
SSL_ENABLE = False
SSL_CERT_FILE = 'cert.pem'  #远端机器的证书

class Server(asyncio.Protocol):
    def __init__(self, host=REMOTE_HOST, port=REMOTE_PORT, timeout=CONNECT_TIMEOUT, loop=None):
        self.tasklist = []
        self.remoteclient = None
        self.transport = None
        self.buffer = asyncio.Queue()
        self.host = host
        self.port = port
        self.timeout = timeout
        self.loop = loop or asyncio.get_event_loop()
        self.closing = False

    def connection_made(self, transport):
        self.transport = transport
        self.ensure_task(self.proxying())

    def ensure_task(self, coro):
        task = asyncio.ensure_future(coro)
        def done(task):
            if task in self.tasklist:
                self.tasklist.remove(task)
        task.add_done_callback(done)
        self.tasklist.append(task)

    def cancel(self, task):
        if not task.done():
            task.cancel()
        if task in self.tasklist:
            self.tasklist.remove(task)

    async def proxying(self):
        context = None
        server_hostname = None
        if SSL_ENABLE:
            context = ssl.create_default_context()
            context.load_verify_locations(SSL_CERT_FILE)
            server_hostname = REMOTE_HOSTNAME
        connect_coro = self.loop.create_connection(lambda: RemoteClientProtocol(self),
            self.host,
            self.port,
            ssl=context,
            server_hostname=server_hostname)
        connect_task = asyncio.ensure_future(connect_coro)
        task = self.loop.call_later(self.timeout, self.cancel, connect_task)
        try:
            _, self.remoteclient = await connect_task
            task.cancel()
        except Exception as e:
            self.close()
            return
        while True:
            try:
                data = await self.buffer.get()
            except:
                break
            self.remoteclient.write(data)
            self.buffer.task_done()

    def write(self, data):
        try:
            self.transport.write(data)
        except:
            self.close()

    def connection_lost(self, ex):
        if not self.closing:
            self.close()

    def close(self):
        if self.closing:
            return
        self.closing = True
        if self.transport and not self.transport.is_closing():
            self.transport.close()
        for task in self.tasklist:
            task.cancel()
        if self.remoteclient:
            self.remoteclient.close()

    def data_received(self, data):
        self.buffer.put_nowait(data)


class RemoteClientProtocol(asyncio.Protocol):
    def __init__(self, server_protocol):
        self.server_protocol = server_protocol
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        self.write = transport.write

    def data_received(self,data):
        if self.server_protocol:
            self.server_protocol.write(data)

    def connection_lost(self, exc):
        self.close()

    def close(self):
        if self.transport is not None and not self.transport.is_closing:
            self.transport.close()
        if self.server_protocol:
            self.server_protocol.close()

def main():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(loop.create_server(Server, HOST, PORT))
    print('Listening on %s:%s...'%(HOST, PORT))
    try:
        loop.run_forever()
    finally:
        loop.close()

if __name__ == '__main__':
    main()
    