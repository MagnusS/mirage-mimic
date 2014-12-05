mimic
=====

This unikernel mimics a host in another network by acquiring a local IP address, opening the same ports and then forwarding all traffic to the remote host through a SOCKS server.

### Build
```
mirage configure --xen
make
```

Edit unikernel.xl to enable networking.

### Set up SOCKS
To set up a SOCKS server with SSH:

```
ssh -D interface:port username@remote_host
```

Replace interface:port with where you want SSH to listen for SOCKS connections. Note that if you set the SOCKS server to listen to localhost in dom0 it will be unavailable to the unikernel.

### Start mimic
Options are set as key=value pairs in the "extra" configuration parameter in Xen. The following options are available:

```
ip=[ip of unikernel on local network]
netmask=[unikernel netmask]
gw=[unikernel gateway]
socks_ip=[ip of socks server relative to unikernel]
socks_port=[port of socks server relative to unikernel]
dest_ip=[ip of remote host relative to other end of ssh tunnel]
dest_ports=[commma separated list of ports to forward/open]
```

The dest_ip and dest_ports parameters refer to a host and list of ports relative to the other end of the SSH tunnel. So if the unikernel should mimic a service running on the same host as you are connect to with SSH you can set dest_ip=127.0.0.1. Otherwise specify an IP on the remote network.

### Example
The following example starts a unikernel that mimics a Squid proxy server in a remote network:

```
xl create unikernel.xl -c 'extra="socks_ip=192.168.56.1 socks_port=8888 dest_ip=127.0.0.1 dest_ports=3128,3127 ip=192.168.56.10 netmask=255.255.255.0 gw=192.168.56.1"'
```

The local SOCKS server in this example runs on 192.168.56.1:8888 (e.g. in dom0). The unikernel is assigned the IP 192.168.56.10 on the local network. Destination ports are 3128 and 3127, which are Squid web proxy ports. Data received by the unikernel on these ports is sent directly through the SOCKS server to IP specified by dest_ip. The IP in dest_ip is relative to the remote endpoint, so in this case Squid is running on localhost on the machine we have an SSH tunnel to.
