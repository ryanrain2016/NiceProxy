#!/usr/bin/env sh

RUN=/var/run/NiceProxy/
NICEPROXY=/usr/app/NiceProxy/
LOG=/var/log/NiceProxy/
SERVICE=/usr/lib/systemd/system/NiceProxy.service

useradd -M -s /sbin/nologin NiceProxy
mkdir -p $NICEPROXY

mkdir -p $LOG
chown -R NiceProxy:NiceProxy $LOG
chmod -R +w $LOG

mkdir -p $RUN
chown -R NiceProxy:NiceProxy $RUN
chmod -R +w $RUN

echo "Copying files..."
cp -Rf NiceProxy.py ${NICEPROXY}NiceProxy
chmod +x ${NICEPROXY}NiceProxy
echo "Copy files done."

echo "generating keys..."
mkdir ${NICEPROXY}keys
openssl req -new -x509 -days 3650 -nodes -out ${NICEPROXY}keys/cert.pem -keyout ${NICEPROXY}keys/key.pem
echo "generating keys done"

chown -R NiceProxy:NiceProxy $NICEPROXY
chmod -R 755 $NICEPROXY

echo "Writing NiceProxy.service..."
echo "" > $SERVICE
chmod 755 $SERVICE
echo "[Unit]"                               >>$SERVICE
echo "Description=NiceProxy"                >>$SERVICE
echo "After=network.target"                 >>$SERVICE
echo ""                                     >>$SERVICE
echo "[Service]"                            >>$SERVICE
echo "Type=forking"                         >>$SERVICE
echo "PIDFile=${RUN}NiceProxy.pid"          >>$SERVICE
echo "ExecStart=${NICEPROXY}NiceProxy"      >>$SERVICE
echo ""                                     >>$SERVICE
echo "[Install]"                            >>$SERVICE
echo "WantedBy=mutil-user.target"           >>$SERVICE
echo ""                                     >>$SERVICE
chmod 754 $SERVICE
echo "Write NiceProxy.service done"

