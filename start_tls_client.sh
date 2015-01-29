SERVER_IP=192.168.2.17
CLIENT_IP=192.168.2.18
WEB_IP=178.79.184.208

echo "Telnet to $CLIENT_IP to connect through $SERVER_IP to $WEB_IP"
sudo xl create unikernel.xl -c 'extra="listen_mode=tcp forward_mode=tls dest_ip='$SERVER_IP' ports=80 ip='$CLIENT_IP' netmask=255.255.255.0 gw=192.168.2.1"' "name='client'" "vif=['bridge=br0']"; sudo xl destroy client


