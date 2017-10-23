# NiceProxy
Sock4/5 and http(s) proxy

+ ����asyncio���첽�������б�֤��֧��Python 3.5+�����uvloop���û�ʹ��uvloop��
+ Ŀǰֻ֧��Sock4/5�����Ĺ��ܣ�û����ȫʵ��rfc1928��
+ http(s)����֧�֡�
+ ���ߺ�����û�а����õĶ���д�������ļ����������У�ֱ�Ӹ�Դ��ǰ���е�ȫ�ֱ������ɡ�
+ ����˸�StraightClient.py,ֻ�ж˿�ת���Ĺ��ܣ�֧��ssl��װ������`SSL_ENABLE = True`�����ɿ�����ʹ����ǩ����֤�鱣֤��ͨѶ�ɿ���ȫ��
+ ����˴�������ssl��װ֧�֣�����`SSL_ENABLE = True`�����ɿ���
+ ����˸�install.sh�Ľű�����������Զ���װ��linux����NiceProxy����*����֤���ʱ��CommonName����*��������Ҫ��StraightClient.py��REMOTE_HOSTNAME����Ϊ���ֵ����Ȼ�����`SSL_ENABLE`���ش򿪵�ʱ�����Ч��
+ HTTP����ʱ��websocketʹ��https/ssl�Ĵ���ʽ������֧�֡�
+ ����ԭ�����شStraightClient.py�����˿ڣ�����Ҫ�����޸�Զ�̻����ĵ�ַ�Ͷ˿ڣ����ؿͻ��ˣ��磺�������ϵͳ������������Ϊ������Ķ˿ڣ�Ĭ����9002����Զ�˻����ϲ���NiceProxy.py�����˿ڣ����ṩ������񡣿ͻ��˵Ĵ��������͸�StraightClient.py,StraightClient.py����ֱ��ת������SSL���ܺ�ת����NiceProxy.py,NiceProxy.py��������Э�飬��ɴ���Ȼ����Ӧԭ·���ء�

# ���𷽷�
## NiceProxy.py
�����Ҫ������Զ�˻�����Ĭ�ϼ���9001�˿ڣ���Ҫ��������Python3�����л���,��Ҫʹ��http(s)/ssl������Ҫ��װhttptools:
```shell
python3 -m pip install -U httptools
```
����
```shell
pip3 install -U httptools
```
### windows
windows�ϲ������ͨ���޸ĺ�׺��Ϊ.pyw������ʹ��pythonw����ִ̨�иýű����������ķ����������á�
### Linux
����NiceProxy.py��install.sh����������ʹ��rootȨ��ִ��install.sh��������뿪��ssl,һ·�س��ͺã������Ҫ����ssl����ô�뿴[SSL֧��](#ssl)��

## StraightClient.py
��������ڱ��أ��޸�Դ����`REMOTE_HOST`��`REMOTE_PORT`ΪԶ�˻����ĵ�ַ�Ͷ˿ڣ�Ȼ��ֱ��ִ�оͺá�
### windows
windows�ϲ������ͨ���޸ĺ�׺��Ϊ.pyw������ʹ��pythonw����ִ̨�иýű�
### Linux
ʹ��supervisord�Ƚ��̹����ߣ�����ִ̨�С�

## SSL
��������SSL��StraightClient.py��StraightClient.pyֱ�ӵ�ͨѶ����ԭʼ���ģ����ؿ��Ժ����׵ĵõ����������ݣ���������Ϊ�˱��������������SSL֧�֣�����ͨѶ���ݵõ����ܣ�ȷ��������ȡ������������ͻ��˺ͷ���˶����Լ��ģ�����SSLʹ����ǩ����֤��ͺá�  
����StraightClient.py��NiceProxy.py�е�`SSL_ENABLE = True`������NiceProxy.pyʱִ��install.shʱ��������֤�飬��ʱ����ʾ����һЩ��Ϣ������������Ҫ���Բ��*CommonNameһ��Ҫ��д*������StraightClient.py�е�`REMOTE_HOSTNAME`Ϊ�����CommonName��Ȼ�󿽱�Զ�˻����ϵ�`/usr/app/NiceProxy/keys/cert.pem`�����أ�����`SSL_CERT_FILE=cert.pem��·��`,��������StraghtClient.py�ͺá�  
ssl֤��Ҳ���������ɺõ�֤�飬ֻ��Ҫ�޸Ķ�Ӧ�ű��еĵ�`SSL_CERT_FILE`��`SSL_KEY_FILE`��

## SOCK5��֤
SOCK5��֤Ĭ�Ϲرգ�`AUTH_REQUIRE`����Ϊ`True`�ɿ���������֮��NiceProxy.py�ű��е�USERNAME��PASSWORD��ֵΪ�û��������롣 FireFox,chrome��ʱ��֧�����ַ�ʽ��������ʱû�����ý���ĳ�ִ���Э�飬������ʱ���岻��

## Nodejs�汾��ִ�в���proxy.jsΪ����ˣ�middle.jsΪ�ͻ��ˡ��������Ҫhttp-proxy,�������ٺö�