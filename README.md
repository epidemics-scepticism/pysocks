# pysocks
simple socks5h implementation in python

a simple usage example:
```
import socks
import socket
s = socket.socket()
s.connect(('127.0.0.1',9050))
lol = socks.socks('fbi.gov',80)
lol.dial(s)
# 127.0.0.1:9050 -> fbi.gov:80
s.send('GET /j-edgar-hoover-dick-pics.jpg HTTP/1.1\r\nHost: fbi.gov\r\n\r\n')
...
```
a more complex example, chaining socks proxies together:
```
import socks
import socket
s = socket.socket()
s.connect(('127.0.0.1', 9050))
lol = socks.socks('1.2.3.4', 1080)
lol.dial(s)
# 127.0.0.1:9050 -> 1.2.3.4:1080
lol.set_host('4.3.2.1')
lol.set_port(8010)
lol.dial(s)
# 127.0.0.1:9050 -> 1.2.3.4:1080 -> 4.3.2.1:8010
lol.set_host('fbi.gov')
lol.set_port(80)
lol.dial(s)
# 127.0.0.1:9050 -> 1.2.3.4:1080 -> 4.3.2.1:8010 -> fbi.gov:80
s.send('GET /j-edgar-hoover-dick-pics.jpg HTTP/1.1\r\nHost: fbi.gov\r\n\r\n')
...
```
