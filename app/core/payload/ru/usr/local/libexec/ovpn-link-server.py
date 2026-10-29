#!/usr/bin/python3
import http.server,socketserver,pathlib,hashlib,json,re,time,base64
ROOT=pathlib.Path('/var/lib/ovpn-links')
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def reply(self,code,body=b'',ctype='text/plain; charset=utf-8',filename=None):
  self.send_response(code);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store, max-age=0');self.send_header('Referrer-Policy','no-referrer');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Security-Policy',"default-src 'none'")
  if filename:self.send_header('Content-Disposition','attachment; filename="'+filename+'"')
  self.end_headers()
  if self.command!='HEAD':self.wfile.write(body)
 def do_GET(self):
  m=re.fullmatch(r'/d/([A-Za-z0-9_-]{22}|[A-Za-z0-9_-]{43})(?:/(?:profile\.ovpn|files\.zip))?',self.path)
  if not m:return self.reply(404,b'Not found')
  path=ROOT/(hashlib.sha256(m[1].encode()).hexdigest()+'.json')
  try:
   d=json.loads(path.read_text())
   if time.time()>=d['expires']:return self.reply(410,'Срок ссылки истёк. Создайте новую ссылку в меню.'.encode())
   if 'archive' in d:
    if self.path.endswith('/profile.ovpn'):return self.reply(404,b'Not found')
    return self.reply(200,base64.b64decode(d['archive']),'application/zip',d['filename'])
   if not self.path.endswith('/profile.ovpn'):return self.reply(404,b'Not found')
   return self.reply(200,d['profile'].encode(),'application/x-openvpn-profile',d['username']+'.ovpn')
  except (FileNotFoundError,ValueError,KeyError):return self.reply(404,b'Not found')
 def do_HEAD(self):self.do_GET()
class Server(socketserver.ThreadingMixIn,http.server.HTTPServer):
 daemon_threads=True
Server(('127.0.0.1',8765),Handler).serve_forever()
