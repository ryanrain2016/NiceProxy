# NiceProxy
Sock4/5 and http(s) proxy

+ 采用asyncio的异步，性能有保证，支持Python 3.5+，如果uvloop可用会使用uvloop。
+ 目前只支持Sock4/5常见的功能，没有完全实现rfc1928。
+ http(s)代理目前没有合并进来。（TODO:）