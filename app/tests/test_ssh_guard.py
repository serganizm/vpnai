import contextlib,json,os,pathlib,select,shlex,subprocess,sys,tempfile,time,types,unittest
try:import fcntl
except ImportError:fcntl=None
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import backend,ssh_guard

@unittest.skipIf(fcntl is None,'Unix descriptor/lock integration tests')
class GuardianProtocol(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name);self.path=str(self.root/'guard.sock');self.lock=str(self.root/'operation.lock');self.token='a'*32;self.children=[];self.addCleanup(self.cleanup)
 def cleanup(self):
  for p in self.children:
   if p.poll() is None:p.kill()
   with contextlib.suppress(Exception):p.communicate(timeout=3)
   for stream in (p.stdin,p.stdout,p.stderr):
    if stream and not stream.closed:stream.close()
 def start(self,lease=2):
  p=subprocess.Popen([sys.executable,'-u','-c',ssh_guard.SERVER,self.path,self.lock,self.token,str(lease)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.children.append(p)
  self.assertTrue(select.select([p.stdout],[],[],3)[0]);self.assertEqual(p.stdout.readline(),b'READY\n');return p
 def available(self):
  with open(self.lock,'a') as f:
   try:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);return True
   except BlockingIOError:return False
 def quit(self,p):p.stdin.write(b'QUIT\n');p.stdin.flush();p.wait(timeout=3)
 def wrapper(self,command,token=None):
  p=subprocess.Popen([sys.executable,'-u','-c',ssh_guard.WRAPPER,self.path,token or self.token,command],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.children.append(p);return p
 def test_normal_completion_releases_and_removes_socket(self):
  p=self.start();self.assertFalse(self.available());self.quit(p);self.assertTrue(self.available());self.assertFalse(pathlib.Path(self.path).exists())
 def test_eof_releases_without_waiting_for_timeout(self):
  p=self.start();p.stdin.close();p.wait(timeout=3);self.assertTrue(self.available())
 def test_lost_connection_without_eof_expires(self):
  p=self.start(.3);p.wait(timeout=3);self.assertTrue(self.available());self.assertFalse(pathlib.Path(self.path).exists())
 def test_heartbeat_keeps_long_action_locked(self):
  p=self.start(.4)
  for _ in range(5):time.sleep(.12);p.stdin.write(b'PING\n');p.stdin.flush()
  self.assertIsNone(p.poll());self.assertFalse(self.available());self.quit(p);self.assertTrue(self.available())
 def test_running_command_remains_protected_after_guard_exits(self):
  guard=self.start();command=shlex.join([sys.executable,'-u','-c',"import time;print('START',flush=True);time.sleep(.8)"])
  child=self.wrapper(command);self.assertEqual(child.stdout.readline(),b'START\n');self.quit(guard)
  self.assertFalse(self.available(),'Active command must retain the shared descriptor')
  child.communicate(timeout=3);self.assertEqual(child.returncode,0);self.assertTrue(self.available())
 def test_command_error_does_not_leave_lock_after_close(self):
  guard=self.start();child=self.wrapper(shlex.join([sys.executable,'-c','raise SystemExit(19)']));child.communicate(timeout=3);self.assertEqual(child.returncode,19);self.quit(guard);self.assertTrue(self.available())
 def test_payload_and_exit_status_are_preserved(self):
  guard=self.start();command=shlex.join([sys.executable,'-c','import json,sys;print(json.load(sys.stdin)["message"])']);child=self.wrapper(command)
  out,err=child.communicate(json.dumps({'message':'Проверка'}).encode(),timeout=3);self.assertEqual(out.decode().strip(),'Проверка');self.assertEqual(child.returncode,0);self.quit(guard)
 def test_foreign_owner_is_never_unlocked(self):
  first=self.start();second=subprocess.Popen([sys.executable,'-u','-c',ssh_guard.SERVER,str(self.root/'other.sock'),self.lock,'b'*32,'1'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.children.append(second)
  out,err=second.communicate(timeout=3);self.assertEqual(second.returncode,73);self.assertEqual(out,b'BUSY\n');self.assertFalse(self.available());self.quit(first)
 def test_wrong_token_cannot_run_commands(self):
  guard=self.start();marker=self.root/'must-not-exist';child=self.wrapper('touch '+shlex.quote(str(marker)),token='b'*32);out,err=child.communicate(timeout=3);self.assertEqual(child.returncode,74);self.assertIn(b'VPNAI_LOCK_LOST',out);self.assertFalse(marker.exists());self.assertFalse(self.available());self.quit(guard)

class RemoteClose(unittest.TestCase):
 def remote(self,fail=False):
  events=[]
  class Channel:
   def shutdown_write(self):events.append('eof')
   def exit_status_ready(self):return True
   def recv_exit_status(self):events.append('ack');return 0
   def close(self):events.append('channel-close')
  class Input:
   def write(self,text):
    events.append(text)
    if fail:raise OSError('Disconnected')
   def flush(self):events.append('flush')
  ch=Channel();remote=backend.Remote('ru',{'host':'8.8.8.8','password':'fixture'});remote.guard=(Input(),types.SimpleNamespace(channel=ch),None);remote.client=types.SimpleNamespace(close=lambda:events.append('client-close'));return remote,events
 def test_close_waits_for_release_before_closing_connection_and_is_idempotent(self):
  remote,events=self.remote();remote.close();self.assertEqual(events,['QUIT\n','flush','eof','ack','channel-close','client-close']);self.assertFalse(remote.lock_release_pending);self.assertEqual(remote.settings,{});remote.close();self.assertEqual(events.count('client-close'),1)
 def test_disconnect_still_closes_transport_and_clears_secrets(self):
  remote,events=self.remote(fail=True);remote.close();self.assertTrue(remote.lock_release_pending);self.assertEqual(events[-1],'client-close');self.assertEqual(remote.settings,{})
