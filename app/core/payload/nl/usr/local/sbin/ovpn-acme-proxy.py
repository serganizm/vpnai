#!/usr/bin/python3
"""Restricted CONNECT relay for ACME; TLS and certificate keys stay on RU."""
import ipaddress,select,socket,socketserver,threading,time
BIND='@@GRE_NL@@'
CLIENT='@@GRE_RU@@'
PORT=18765
HOSTS={'acme-v02.api.letsencrypt.org','acme-staging-v02.api.letsencrypt.org'}
SLOTS=threading.BoundedSemaphore(16)
def parse_target(line):
 parts=line.split()
 if len(parts)!=3 or parts[0]!='CONNECT' or parts[2] not in ('HTTP/1.0','HTTP/1.1'):raise ValueError('method')
 host,sep,port=parts[1].rpartition(':')
 if not sep or host not in HOSTS or port!='443':raise ValueError('target')
 return host

def upstream(host):
 if host not in HOSTS:raise ValueError('host')
 for family,kind,protocol,_,addr in socket.getaddrinfo(host,443,socket.AF_INET,socket.SOCK_STREAM):
  if not ipaddress.ip_address(addr[0]).is_global:continue
  s=socket.socket(family,kind,protocol);s.settimeout(10)
  try:s.connect(addr);return s
  except OSError:s.close()
 raise OSError('No reachable global ACME endpoint')

def relay(client,remote):
 deadline=time.monotonic()+180
 while time.monotonic()<deadline:
  ready,_,_=select.select([client,remote],[],[],30)
  if not ready:return
  for source in ready:
   data=source.recv(65536)
   if not data:return
   (remote if source is client else client).sendall(data)

class Handler(socketserver.BaseRequestHandler):
 def handle(self):
  if self.client_address[0]!=CLIENT or not SLOTS.acquire(blocking=False):return
  try:
   self.request.settimeout(15)
   header=b''
   while b'\r\n\r\n' not in header:
    data=self.request.recv(1)
    if not data or len(header)>=8192:raise ValueError('header')
    header+=data
   host=parse_target(header.split(b'\r\n',1)[0].decode('ascii'))
   with upstream(host) as remote:
    self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
    relay(self.request,remote)
  except (OSError,ValueError,UnicodeError):
   try:self.request.sendall(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
   except OSError:pass
  finally:SLOTS.release()

class Server(socketserver.ThreadingMixIn,socketserver.TCPServer):
 allow_reuse_address=True
 daemon_threads=True
 request_queue_size=16
if __name__=='__main__':
 with Server((BIND,PORT),Handler) as server:server.serve_forever()
