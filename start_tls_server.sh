SERVER_IP=192.168.2.17
CLIENT_IP=192.168.2.18
WEB_IP=178.79.184.208

sudo xl create unikernel.xl -c 'extra="listen_mode=tls forward_mode=tcp dest_ip='$WEB_IP' ports=80 ip='$SERVER_IP' netmask=255.255.255.0 gw=192.168.2.1"' "name='server'" "vif=['bridge=br0']"; sudo xl destroy server


