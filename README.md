# NiceProxy
Sock4/5 and http(s) proxy

+ 采用asyncio的异步，性能有保证，支持Python 3.5+，如果uvloop可用会使用uvloop。
+ 目前只支持Sock4/5常见的功能，没有完全实现rfc1928。
+ http(s)代理支持。
+ 作者很懒，没有把配置的东西写成配置文件或者命令行，直接改源码前几行的全局变量即可。
+ 添加了个StraightClient.py,只有端口转发的功能，支持ssl封装，设置`SSL_ENABLE = True`，即可开启，使用自签名的证书保证，通讯可靠安全。
+ 添加了代理请求ssl封装支持，设置`SSL_ENABLE = True`，即可开启
+ 添加了个install.sh的脚本，将代理端自动安装成linux服务（NiceProxy），*生成证书的时候CommonName必填*，并且需要将StraightClient.py的REMOTE_HOSTNAME设置为这个值。当然这个在`SSL_ENABLE`开关打开的时候才生效。
+ HTTP代理时，websocket使用https/ssl的代理方式，可以支持。
+ 工作原理：本地搭建StraightClient.py监听端口，并需要配置修改远程机器的地址和端口，本地客户端（如：浏览器，系统代理）代理设置为其监听的端口（默认是9002）；远端机器上部署NiceProxy.py监听端口，并提供代理服务。客户端的代理请求发送给StraightClient.py,StraightClient.py将其直接转发或者SSL加密后转发给NiceProxy.py,NiceProxy.py解析代理协议，完成代理，然后响应原路返回。

# 部署方法
## NiceProxy.py
这个需要部署在远端机器，默认监听9001端口，需要机器上有Python3的运行环境,若要使用http(s)/ssl代理，需要安装httptools:
```shell
python3 -m pip install -U httptools
```
或者
```shell
pip3 install -U httptools
```
### windows
windows上部署可以通过修改后缀名为.pyw，或者使用pythonw来后台执行该脚本。自启动的方法自行配置。
### Linux
拷贝NiceProxy.py和install.sh到服务器，使用root权限执行install.sh。如果不想开启ssl,一路回车就好；如果需要开启ssl，那么请看[SSL支持](#ssl)。

## StraightClient.py
这个部署在本地，修改源码中`REMOTE_HOST`和`REMOTE_PORT`为远端机器的地址和端口，然后直接执行就好。
### windows
windows上部署可以通过修改后缀名为.pyw，或者使用pythonw来后台执行该脚本
### Linux
使用supervisord等进程管理工具，来后台执行。

## SSL
若不开启SSL，StraightClient.py和StraightClient.py直接的通讯都是原始报文，网关可以很容易的得到交互的数据，并监听。为了保密起见可以启用SSL支持，这样通讯内容得到加密，确保不被窃取，监听。这里客户端和服务端都是自己的，所以SSL使用自签名的证书就好。  
设置StraightClient.py，NiceProxy.py中的`SSL_ENABLE = True`，部署NiceProxy.py时执行install.sh时，会生成证书，这时会提示输入一些信息，其他都不重要可以不填，*CommonName一定要填写*。设置StraightClient.py中的`REMOTE_HOSTNAME`为填入的CommonName，然后拷贝远端机器上的`/usr/app/NiceProxy/keys/cert.pem`到本地，设置`SSL_CERT_FILE=cert.pem的路径`,重新启动StraghtClient.py就好。  
ssl证书也可以是生成好的证书，只需要修改对应脚本中的的`SSL_CERT_FILE`和`SSL_KEY_FILE`。

## SOCK5验证
SOCK5验证默认关闭，`AUTH_REQUIRE`设置为`True`可开启，开启之后NiceProxy.py脚本中的USERNAME和PASSWORD的值为用户名和密码。 FireFox,chrome暂时不支持这种方式，并且暂时没有配置禁用某种代理协议，所以暂时意义不大。

## Nodejs版本的执行部署，proxy.js为服务端，middle.js为客户端。服务端需要http-proxy,代码量少好多额。