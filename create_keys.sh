#!/bin/sh
openssl genrsa -out demo_keys/tls/server.key 2048
openssl req -new -x509 -key demo_keys/tls/server.key -out demo_keys/tls/server.pem -days 1095
