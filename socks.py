#!/usr/bin/python2

#    Copyright (C) 2016 cacahuatl < cacahuatl at autistici dot org >
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import socket,struct

def send_all(s, payload):
    """Ugly hack to send all"""
    sent = 0
    while sent < len(payload):
        tmp = s.send(payload[sent:])
        if tmp > 0:
            sent += tmp

def recv_all(s, buflen):
    """Ugly hack to recv all"""
    tmp = ''
    while len(tmp) < buflen:
        tmp += s.recv(buflen - len(tmp))
    return tmp

# >>> import socks
# >>> lol = socks.socks('fbi.gov',80)
# >>> s = lol.lazy_dev('127.0.0.1',9050)
# >>> s.send('GET / HTTP/1.1\r\nHost: fbi.gov.\r\n\r\n')
# >>> s.recv(4096)
# 'HTTP/1.0 301 Moved Permanently\r\nLocation: https://www.fbi.gov/\r\nContent-Length: 224\r\n\r\n<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd"><html><head><title>Web Forwarding</title><meta http-equiv="Content-Type" content="text/html;charset=utf-8"></head><body></body></html>'

class socks():
    """Provides a simple SOCKS5H implementation"""
    version = 5
    methods = [2, 0]
    failcodes = {
            0: 'success',
            1: 'general SOCKS server failure',
            2: 'connection not allowed by ruleset',
            3: 'network unreachable',
            4: 'host unreachable',
            5: 'connection refused',
            6: 'TTL expired',
            7: 'command not supported',
            8: 'address type not supported',
            }
    def __init__(self, h='fbi.gov', p=80, user='', passwd=''):
        self.set_host(h)
        self.set_port(p)
        self.set_user(user)
        self.set_pass(passwd)
    def set_host(self, h=None):
        if h != None:
            h = str(h)
            if len(h) > 255:
                raise Exception('Hostname must be less than 256 bytes: got %d bytes' % len(h))
            self.h = h
    def set_port(self, p=None):
        if p != None:
            self.p = int(p)
    def set_user(self, s=None):
        if s != None:
            user = str(s)
            if len(user) > 255:
                raise Exception('Username must be less than 256 bytes: got %d bytes' % len(user))
            self.user = user
    def set_pass(self, s=None):
        if s != None:
            passwd = str(s)
            if len(passwd) > 255:
                raise Exception('Password must be less than 256 bytes: got %d bytes' % len(passwd))
            self.passwd = passwd
    def dial(self, s):
        self.negotiate_auth(s)
        self.negotiate_connection(s)
    def negotiate_auth(self, s):
        payload = struct.pack('!BB', self.version, len(self.methods))
        for method in self.methods:
            payload += struct.pack('!B', method)
        send_all(s, payload)
        v, m = struct.unpack('!BB', recv_all(s, 2))
        if v != 5:
            raise Exception('Invalid SOCKS version: %d' % v)
        if not m in self.methods:
            raise Exception('Unsupported authentication type: %d' % m)
        if m is 2:
            self.userpassauth(s)
    def userpassauth(self, s):
        payload  = struct.pack('!BB', 1, len(self.user))
        payload += self.user
        payload += struct.pack('!B', len(self.passwd))
        payload += self.passwd
        send_all(s, payload)
        v, s = struct.unpack('!BB', recv_all(s, 2))
        if v != 1:
            raise Exception('Invalid SOCKS User/Pass version: %d' % v)
        if s != 0:
            raise Exception('Invalid SOCKS User/Pass credentials: %d' % status)
    def conn_fail(self, r):
        return self.failcodes.get(r, "unknown")
    def negotiate_connection(self, s):
        payload  = struct.pack("!BBBB", self.version, 1, 0, 3)
        payload += struct.pack("!B", len(self.h))
        payload += self.h
        payload += struct.pack('!H', int(self.p))
        send_all(s, payload)
        v, r, _, t = struct.unpack('!BBBB', recv_all(s, 4))
        if v != 5:
            raise Exception('Invalid SOCKS version: %d' % v)
        if r != 0:
            raise Exception('Failed to connect: %s' % self.conn_fail(r))
        if t == 1: # ipv4 + port
            _ = recv_all(s, 6)
        elif t == 4: # ipv6 + port
            _ = recv_all(s, 18)
        elif t == 3: # domain name + port
            l, = struct.unpack('!B', recv_all(s, 1))
            _ = recv_all(s, l + 2)
        else:
            raise Exception('Invalid address type: %d' % t)
    def lazy_dev(self, sockshost='127.0.0.1', socksport=9050):
        s = socket.socket()
        s.connect((str(sockshost),int(socksport)))
        self.dial(s)
        return s
