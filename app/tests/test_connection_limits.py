import contextlib,copy,hashlib,json,pathlib,shlex,shutil,subprocess,sys,tempfile,threading,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import limits_backend as client,limits_remote as remote,session_limits as counter,backend
class ClientValidation(unittest.TestCase):
 def test_limits_have_strict_integer_bounds(self):
  for value in [True,False,'2',1.2,-1,1001,{},None]:
   with self.subTest(value=value),self.assertRaises(backend.UserError):client.validate(value)
  for value in [0,1,1000]:self.assertEqual(client.validate(value),value)
  self.assertIsNone(client.validate(None,True))
class OpenVPNCommandSyntax(unittest.TestCase):
 def commands(self):
  for name in ['ru.conf','ru-tcp.conf']:
   for line in (ROOT/'core/payload/ru/etc/openvpn/server'/name).read_text().splitlines():
    if line.startswith(('client-connect ','client-disconnect ')):yield line
 def test_hooks_have_exactly_one_command_argument(self):
  for line in self.commands():
   parts=shlex.split(line);self.assertEqual(len(parts),2,line);self.assertEqual(len(shlex.split(parts[1])),2,line)
 @unittest.skipUnless(shutil.which('openvpn') or pathlib.Path('/usr/sbin/openvpn').exists(),'OpenVPN parser not installed on this OS')
 def test_real_openvpn_parser_accepts_generated_hooks(self):
  binary=shutil.which('openvpn') or '/usr/sbin/openvpn'
  with tempfile.TemporaryDirectory() as folder:
   config=pathlib.Path(folder)/'test.conf'
   for mode in ['connect','connect-full']:
    lines=[line.replace('/usr/local/libexec/ovpn-session-limit','/bin/true').replace(' connect"',' '+mode+'"') for line in self.commands()]
    config.write_text('\n'.join(dict.fromkeys(lines))+'\n')
    result=subprocess.run([binary,'--config',str(config),'--show-ciphers'],capture_output=True,text=True,timeout=10)
    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
@unittest.skipIf(sys.platform=='win32','Linux server flock/proc integration simulated on Unix')
class LimitsIntegration(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name);self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
  for module in [counter,remote]:
   self.stack.enter_context(patch.object(module,'POLICY',self.root/'connection-limits.json'))
   self.stack.enter_context(patch.object(module,'CERTS',self.root/'certs'))
  self.stack.enter_context(patch.object(counter,'RUNTIME',self.root/'runtime'));self.stack.enter_context(patch.object(counter,'process_stamp',lambda pid:'generation-one' if pid!=998 else None))
  self.stack.enter_context(patch.object(remote,'CONF',[self.root/'ru.conf',self.root/'ru-tcp.conf']));self.stack.enter_context(patch.object(remote,'HELPER',self.root/'hook'));self.stack.enter_context(patch.object(remote,'BACKUPS',self.root/'backups'))
  self.root.joinpath('certs').mkdir();self.root.joinpath('certs/alice.crt').write_text('CERT-A');self.root.joinpath('users.json').write_text(json.dumps({'alice':{'enabled':True},'bob':{'enabled':True}}))
  for f in remote.CONF:f.write_text('dev tun-test\npush "dhcp-option DNS 8.8.8.8"\nclient-connect '+remote.HOOK+'\n')
  self.env={'common_name':'alice','dev':'tun-ovpn','trusted_ip':'8.8.8.8','trusted_port':'50000','ifconfig_pool_remote_ip':'10.77.0.2','time_unix':'1234'};self.commands=[];self.fail=False
  def run(args,**kw):
   self.commands.append(args)
   if args[:2]==['systemctl','restart'] and self.fail:self.fail=False;raise subprocess.CalledProcessError(1,args)
   return subprocess.CompletedProcess(args,0,'','')
  self.stack.enter_context(patch.object(remote.subprocess,'run',side_effect=run))
  import builtins
  original=builtins.open
  self.stack.enter_context(patch('builtins.open',lambda p,*a,**kw:original(self.root/'user.lock' if str(p)=='/run/ovpn-user.lock' else p,*a,**kw)))
 def update(self,value=2,operation='default',**extra):
  return remote.execute(dict(operation=operation,value=value,name='alice',revision=remote.read()['revision'],confirmed=True,restart_confirmed=True,helper=(ROOT/'session_limits.py').read_text(),**extra))
 def test_read_is_non_mutating_and_old_server_is_unlimited(self):
  before=list(self.root.rglob('*'));r=remote.read();self.assertEqual(r['default'],0);self.assertFalse(r['installed']);self.assertEqual(before,list(self.root.rglob('*')))
 def test_first_enable_preserves_routing_auth_and_requires_confirmation(self):
  with self.assertRaisesRegex(ValueError,'перезапуска'):remote.execute(dict(operation='default',value=2,revision=remote.read()['revision'],confirmed=True))
  self.assertFalse(remote.POLICY.exists());r=self.update();self.assertTrue(r['installed']);self.assertTrue(r['restarted'])
  for f in remote.CONF:self.assertIn('dhcp-option DNS 8.8.8.8',f.read_text());self.assertIn('client-disconnect',f.read_text())
  self.assertTrue(remote.HELPER.read_text().startswith('#!/usr/bin/python3\n'));self.assertEqual(remote.POLICY.stat().st_mode&0o777,0o600)
 def test_later_changes_do_not_restart_or_disconnect(self):
  self.update();self.commands.clear();self.update(1);self.assertEqual(self.commands,[])
 def test_shared_udp_tcp_limit_is_atomic_under_parallel_connects(self):
  self.update(2);barrier=threading.Barrier(16);accepted=[];rejected=[]
  def enter(i):
   env=dict(self.env,trusted_port=str(50000+i),dev='tun-ovpn' if i%2 else 'tun-ovpn-tcp',ifconfig_pool_remote_ip='10.77.0.'+str(i+2));barrier.wait()
   try:accepted.append(counter.reserve(env,pid=100)[0])
   except ValueError:rejected.append(i)
  threads=[threading.Thread(target=enter,args=(i,)) for i in range(16)]
  for t in threads:t.start()
  for t in threads:t.join(timeout=10);self.assertFalse(t.is_alive())
  self.assertEqual(len(accepted),2);self.assertEqual(len(rejected),14)
 def test_user_override_inheritance_unlimited_and_new_certificate(self):
  self.update(1);self.update(0,operation='user');counter.reserve(self.env,100);counter.reserve(dict(self.env,trusted_port='50001',ifconfig_pool_remote_ip='10.77.0.3'),100)
  self.root.joinpath('certs/alice.crt').write_text('NEW-CERT');self.assertNotIn('alice',remote.read()['users'])
  with self.assertRaises(ValueError):counter.reserve(dict(self.env,trusted_port='50002',ifconfig_pool_remote_ip='10.77.0.4'),100)
 def test_inherit_removes_only_the_requested_override(self):
  self.update(3);self.update(1,operation='user');self.assertEqual(remote.read()['users']['alice'],1);self.update(None,operation='user');self.assertNotIn('alice',remote.read()['users']);self.assertEqual(remote.read()['default'],3)
 def test_disconnect_releases_exactly_one_session(self):
  self.update(2);key,_=counter.reserve(self.env,100);other,_=counter.reserve(dict(self.env,trusted_port='50001',ifconfig_pool_remote_ip='10.77.0.3'),100);counter.release(key)
  counter.reserve(dict(self.env,trusted_port='50002',ifconfig_pool_remote_ip='10.77.0.4'),100)
  with counter.ledger() as rows:self.assertIn(other,rows);self.assertEqual(len(rows),2)
 def test_decrease_preserves_all_live_sessions_and_blocks_new(self):
  self.update(0)
  for i in range(4):counter.reserve(dict(self.env,trusted_port=str(50000+i),ifconfig_pool_remote_ip='10.77.0.'+str(i+2)),100)
  self.update(1)
  with self.assertRaises(ValueError):counter.reserve(dict(self.env,trusted_port='60000',ifconfig_pool_remote_ip='10.77.0.6'),100)
  with counter.ledger() as rows:self.assertEqual(len(rows),4)
 def test_dead_daemon_slots_are_pruned_but_live_slots_do_not_expire(self):
  self.update(1);counter.RUNTIME.mkdir();counter.atomic(counter.RUNTIME/'sessions.json',{'old':{'name':'alice','pid':998,'stamp':'old','created':0}});counter.reserve(self.env,100)
  with self.assertRaises(ValueError):counter.reserve(dict(self.env,trusted_port='50002',ifconfig_pool_remote_ip='10.77.0.4'),100)
 def test_bad_policy_fails_closed(self):
  self.update();remote.POLICY.write_text('{invalid')
  with self.assertRaises(ValueError):counter.reserve(self.env,100)
 def test_route_hook_failure_removes_reservation(self):
  self.update(1)
  with patch.dict(counter.os.environ,self.env),patch.object(counter.os,'getppid',return_value=100),patch.object(counter.subprocess,'run',side_effect=RuntimeError('route failed')):
   with self.assertRaises(RuntimeError):counter.hook('connect',['/tmp/private-client-config'])
  with counter.ledger() as rows:self.assertEqual(rows,{})
 def test_restart_failure_restores_original_files_and_policy(self):
  before={f:f.read_bytes() for f in remote.CONF};self.fail=True
  with self.assertRaisesRegex(ValueError,'восстановлены'):self.update()
  self.assertFalse(remote.POLICY.exists());self.assertFalse(remote.HELPER.exists())
  for f,body in before.items():self.assertEqual(f.read_bytes(),body)
 def test_foreign_hooks_and_stale_revision_never_write(self):
  remote.CONF[0].write_text('client-connect /root/foreign-hook\n');before=remote.CONF[0].read_bytes()
  with self.assertRaisesRegex(ValueError,'замена запрещена'):self.update()
  self.assertEqual(remote.CONF[0].read_bytes(),before);self.assertFalse(remote.POLICY.exists())
  with self.assertRaisesRegex(ValueError,'изменились'):remote.execute({'operation':'default','value':1,'revision':'bad','confirmed':True,'restart_confirmed':True})

 def test_old_user_dialog_rejects_a_reissued_certificate(self):
  current=self.update(2);self.root.joinpath('certs/alice.crt').write_text('REISSUED-CERT')
  with self.assertRaisesRegex(ValueError,'изменились'):
   remote.execute(dict(operation='user',name='alice',value=1,revision=current['revision'],confirmed=True,restart_confirmed=True))
  self.assertEqual(remote.read()['users'],{})

 def test_nat_rebind_keeps_the_same_session_identity(self):
  self.update(1);key,created=counter.reserve(self.env,100);same,created_again=counter.reserve(dict(self.env,trusted_ip='1.1.1.1',trusted_port='65000'),100);self.assertEqual(key,same);self.assertFalse(created_again)
  with counter.ledger() as rows:self.assertEqual(len(rows),1)

 def test_full_tunnel_uses_quoted_connect_full_and_is_detected(self):
  for f in remote.CONF:f.write_text('dev tun-test\npush "redirect-gateway def1"\n')
  self.update(2);self.assertTrue(remote.read()['installed'])
  for f in remote.CONF:
   hooks=[shlex.split(line) for line in f.read_text().splitlines() if line.startswith(('client-connect ','client-disconnect '))]
   self.assertTrue(all(len(row)==2 for row in hooks));self.assertEqual(shlex.split(hooks[0][1])[-1],'connect-full')
 def test_preflight_error_never_restarts_services_and_shows_reason(self):
  original={f:f.read_bytes() for f in remote.CONF}
  run=remote.subprocess.run.side_effect
  def fail(args,**kw):
   if args[0]=='openvpn':raise subprocess.CalledProcessError(1,args,output='Options error: fixture failure')
   return run(args,**kw)
  with patch.object(remote.subprocess,'run',side_effect=fail):
   with self.assertRaisesRegex(ValueError,'Options error: fixture failure'):self.update(2)
  self.assertFalse(any(args[:2]==['systemctl','restart'] for args in self.commands))
  for f,body in original.items():self.assertEqual(f.read_bytes(),body)
  self.assertFalse(remote.HELPER.exists());self.assertFalse(remote.POLICY.exists())
