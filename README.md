# NiceProxy
Sock4/5 and http(s) proxy

+ 采用asyncio的异步，性能有保证，支持Python 3.5+，如果uvloop可用会使用uvloop。
+ 目前只支持Sock4/5常见的功能，没有完全实现rfc1928。
+ http(s)代理支持。
+ 作者很懒，没有把配置的东西写成配置文件或者命令行，直接改源码前几行的全局变量即可。
+ 添加了个StraightClient.py,只有端口转发的功能，支持ssl封装，设置SSL_ENABLE = True，即可开启
+ 添加了代理请求ssl封装支持，设置SSL_ENABLE = True，即可开启
+ 添加了个install.sh的脚本，将代理端自动安装成linux服务（NiceProxy），生成证书的时候CommonName必填，并且需要将StraightClient.py的REMOTE_HOSTNAME设置为这个值。当然这个在SSL_ENABLE开关打开的时候才生效。
+ windows将文件后缀改成pyw，双击即可以后台运行
+ HTTP代理时，websocket使用https/ssl的代理方式，可以支持。
