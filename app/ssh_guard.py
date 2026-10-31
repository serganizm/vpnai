"""Scoped SSH lock with a heartbeat and descriptor inheritance for live commands."""
import shlex
LEASE_SECONDS=45
HEARTBEAT_SECONDS=10
SERVER=r'''
import array,fcntl,os,select,socket,sys,time
path,lockpath,token,lease=sys.argv[1:];lease=float(lease)
lock=open(lockpath,'a');listener=None;inode=None
try:
 try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 except BlockingIOError:print('BUSY',flush=True);raise SystemExit(73)
 listener=socket.socket(socket.AF_UNIX);listener.bind(path);os.chmod(path,0o600);inode=os.stat(path).st_ino;listener.listen(4)
 print('READY',flush=True);deadline=time.monotonic()+lease;buffer=b'';done=False
 while not done:
  remaining=deadline-time.monotonic()
  if remaining<=0:break
  readable,_,_=select.select([sys.stdin.fileno(),listener],[],[],remaining)
  if not readable:break
  if sys.stdin.fileno() in readable:
   block=os.read(sys.stdin.fileno(),4096)
   if not block:break
   buffer+=block
   if len(buffer)>4096:break
   while b'\n' in buffer:
    line,buffer=buffer.split(b'\n',1)
    if line==b'PING':deadline=time.monotonic()+lease
    elif line==b'QUIT':done=True;break
    else:done=True;break
  if not done and listener in readable:
   conn,_=listener.accept()
   with conn:
    conn.settimeout(2);received=b''
    try:
     while len(received)<len(token):
      part=conn.recv(len(token)-len(received))
      if not part:break
      received+=part
     if received.decode('ascii','replace')==token:
      conn.sendmsg([b'L'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[lock.fileno()]))])
    except (OSError,TimeoutError):pass
finally:
 if listener:listener.close()
 if inode is not None:
  try:
   if os.stat(path).st_ino==inode:os.unlink(path)
  except FileNotFoundError:pass
 # Do not LOCK_UN here: a running command may still own this open-file description.
 lock.close()
print('RELEASED',flush=True)
'''
WRAPPER=r'''
import array,os,socket,subprocess,sys
path,token,command=sys.argv[1:]
try:
 with socket.socket(socket.AF_UNIX) as connection:
  connection.settimeout(5);connection.connect(path);connection.sendall(token.encode('ascii'))
  message,ancillary,flags,address=connection.recvmsg(1,socket.CMSG_SPACE(array.array('i').itemsize))
  fds=array.array('i')
  for level,kind,data in ancillary:
   if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:fds.frombytes(data[:len(data)-(len(data)%fds.itemsize)])
  if message!=b'L' or len(fds)!=1:raise OSError('Lock descriptor unavailable')
  fd=fds[0]
except OSError:
 print('VPNAI_LOCK_LOST',flush=True);raise SystemExit(74)
try:
 # The shell and foreground command retain the shared lock even if the guardian times out.
 result=subprocess.run(command,shell=True,pass_fds=(fd,))
finally:os.close(fd)
raise SystemExit(result.returncode)
'''
def server_command(path,token,lockpath='/run/ovpn-installer.lock',lease=LEASE_SECONDS):
 return 'python3 -u -c '+shlex.quote(SERVER)+' '+shlex.join([path,lockpath,token,str(lease)])
def protected_command(command,path,token):
 return 'python3 -u -c '+shlex.quote(WRAPPER)+' '+shlex.join([path,token,command])
