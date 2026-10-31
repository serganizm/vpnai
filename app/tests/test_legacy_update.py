import ast,contextlib,hashlib,importlib.util,json,pathlib,sys,tempfile,types,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import backend,legacy_update,legacy_update_remote as remote

@unittest.skipIf(sys.platform=='win32','Server-side Unix lock and file permission tests')
class LegacyAuthentication(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name);self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
  for name,value in {'CONF':[str(self.root/'ru.conf'),str(self.root/'ru-tcp.conf')],'USERS':str(self.root/'users.json'),'UTILITY':str(self.root/'ovpn-user'),'NETWORK':str(self.root/'network'),'AUTH':str(self.root/'auth.py'),'LISTS':[str(self.root/'ru.txt'),str(self.root/'eu.txt')],'EXTRA':[str(self.root/'dns.json'),str(self.root/'dns-helper')],'PROFILE_DIR':str(self.root/'profiles'),'BACKUPS':str(self.root/'backups')}.items():self.stack.enter_context(patch.object(remote,name,value))
  self.data={'ru_ip':'8.8.8.8','nl_ip':'9.9.9.9'};self.active={'openvpn-server@ru.service':True,'openvpn-server@ru-tcp.service':True};self.commands=[];self.fail=False
  for i,p in enumerate(remote.CONF):pathlib.Path(p).write_text('dev tun-test\nport 1194\nserver '+('10.77.0.0' if i==0 else '10.79.0.0')+' 255.255.255.0\nverify-client-cert require\nauth-user-pass-verify '+remote.AUTH+' via-file\nclient-connect /usr/local/libexec/ovpn-split-connect\npush "dhcp-option DNS 8.8.8.8"\n')
  self.base='client\nproto udp4\nremote 8.8.8.8 1194\nauth-user-pass\nremote-cert-tls server\n'
  pathlib.Path(remote.UTILITY).write_text('def create_profiles(name):\n profile='+repr(self.base)+'\n return profile\n')
  pathlib.Path(remote.NETWORK).write_text('--match-set ovpn_nl');pathlib.Path(remote.AUTH).write_text('AUTHENTICATOR_UNCHANGED')
  salt='ab'*16;password='existing-password';digest=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),300000).hex()
  pathlib.Path(remote.USERS).write_text(json.dumps({'alice':{'enabled':True,'comment':'KEEP','salt':salt,'hash':digest}}));pathlib.Path(remote.PROFILE_DIR).mkdir()
  for suffix in ('.ovpn','-UDP.ovpn','-TCP.ovpn'):
   body=self.base.replace('proto udp4','proto tcp4-client') if suffix=='-TCP.ovpn' else self.base
   body+='\n<ca>\nCA_UNCHANGED\n</ca>\n<cert>\nCERT_UNCHANGED\n</cert>\n<key>\nKEY_UNCHANGED\n</key>\n<tls-crypt>\nTLS_UNCHANGED\n</tls-crypt>\n'
   pathlib.Path(remote.PROFILE_DIR,'alice'+suffix).write_text(body)
  pathlib.Path(remote.PROFILE_DIR,'alice-credentials.txt').write_text('Login: alice\nPassword: '+password+'\n')
  pathlib.Path(remote.LISTS[0]).write_text('8.8.8.0/24\n1.1.1.1\n');pathlib.Path(remote.LISTS[1]).write_text('')
  for p in remote.EXTRA:pathlib.Path(p).write_text('DNS_UNCHANGED')
  self.stack.enter_context(patch.object(remote,'command',self.command))
  import builtins
  original=builtins.open
  def opened(path,*args,**kwargs):return original(self.root/'user.lock' if str(path)=='/run/ovpn-user.lock' else path,*args,**kwargs)
  self.stack.enter_context(patch('builtins.open',opened))
 def command(self,args,check=True):
  self.commands.append(args);code=0;out=''
  if args[0]=='ip':out=json.dumps([{'linkinfo':{'info_kind':'gre','info_data':{'local':'8.8.8.8','remote':'9.9.9.9'}}}])
  elif args[:2]==['systemctl','is-active']:code=0 if self.active.get(args[-1]) else 3
  elif args[:2]==['systemctl','stop']:
   for u in args[2:]:self.active[u]=False
  elif args[:2]==['systemctl','restart']:
   if self.fail:self.fail=False;raise ValueError('Injected restart failure')
   for u in args[2:]:self.active[u]=True
  else:raise AssertionError(args)
  return types.SimpleNamespace(returncode=code,stdout=out)
 def read(self):return remote.snapshot(self.data)[0]
 def apply(self,auth='certificate',**extra):return remote.apply(dict(self.data,auth=auth,confirmed=True,revision=self.read()['revision'],**extra))
 def all_files(self):return {str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file() and 'backups' not in p.parts and p.name!='user.lock'}
 def test_read_only_live_load_includes_actual_routes_and_needs_no_metadata(self):
  before=self.all_files();r=self.read();self.assertTrue(r['legacy']);self.assertEqual(r['config']['auth_mode'],'password');self.assertEqual(r['ru_routes'],['1.1.1.1/32','8.8.8.0/24']);self.assertEqual(self.all_files(),before);self.assertTrue(all(c[0]=='ip' for c in self.commands));self.assertFalse((self.root/'user.lock').exists())
 def test_certificate_and_password_switch_preserves_users_keys_dns_and_lists(self):
  before=self.all_files();answer=self.apply();self.assertEqual(answer['config']['auth_mode'],'certificate')
  for p in remote.CONF:self.assertNotIn('auth-user-pass-verify',pathlib.Path(p).read_text());self.assertIn('dhcp-option DNS 8.8.8.8',pathlib.Path(p).read_text())
  _,t=remote.template(pathlib.Path(remote.UTILITY).read_text());self.assertNotIn('auth-user-pass',t.value)
  for suffix in ('.ovpn','-UDP.ovpn','-TCP.ovpn'):
   text=pathlib.Path(remote.PROFILE_DIR,'alice'+suffix).read_text();self.assertNotIn('auth-user-pass',text);self.assertIn('KEY_UNCHANGED',text);self.assertIn('CERT_UNCHANGED',text)
  for path in [remote.USERS,remote.AUTH,*remote.LISTS,*remote.EXTRA,str(pathlib.Path(remote.PROFILE_DIR,'alice-credentials.txt'))]:self.assertEqual(pathlib.Path(path).read_bytes(),before[str(pathlib.Path(path).relative_to(self.root))])
  self.assertEqual(self.apply('password')['config']['auth_mode'],'password');self.assertEqual(self.read()['user_count'],1)
 def test_stale_revision_refused_without_writes_or_restart(self):
  revision=self.read()['revision'];pathlib.Path(remote.LISTS[0]).write_text('8.8.8.8\n');before=self.all_files()
  with self.assertRaisesRegex(ValueError,'изменились'):remote.apply(dict(self.data,auth='certificate',confirmed=True,revision=revision))
  self.assertEqual(self.all_files(),before);self.assertFalse(any(c[0]=='systemctl' for c in self.commands))
 def test_restart_failure_restores_exact_files_and_active_services(self):
  before=self.all_files();self.fail=True
  with self.assertRaisesRegex(ValueError,'Прежние настройки восстановлены'):self.apply()
  self.assertEqual(self.all_files(),before);self.assertTrue(all(self.active.values()))
 def test_inactive_tcp_is_not_started(self):
  self.active['openvpn-server@ru-tcp.service']=False;self.apply();self.assertFalse(self.active['openvpn-server@ru-tcp.service'])
 def test_wrong_peer_and_unconfirmed_update_do_not_write(self):
  before=self.all_files()
  with self.assertRaisesRegex(ValueError,'другой паре'):remote.snapshot(dict(self.data,nl_ip='1.1.1.1'))
  with self.assertRaisesRegex(ValueError,'подтверждено'):remote.apply(dict(self.data,auth='certificate',revision=self.read()['revision'],confirmed=False))
  self.assertEqual(self.all_files(),before)
 def test_unchanged_auth_has_no_backup_or_restart(self):
  self.assertTrue(self.apply('password')['unchanged']);self.assertFalse(pathlib.Path(remote.BACKUPS).exists());self.assertFalse(any(c[0]=='systemctl' for c in self.commands))
 def test_unverified_password_is_not_silently_generated(self):
  self.apply();pathlib.Path(remote.PROFILE_DIR,'alice-credentials.txt').write_text('Login: alice\n');before=self.all_files()
  with self.assertRaisesRegex(ValueError,'нет проверенного'):self.apply('password')
  self.assertEqual(self.all_files(),before)

class LegacyAdapter(unittest.TestCase):
 def test_update_configuration_delegates_missing_state_to_live_reader(self):
  with patch.object(legacy_update,'read',return_value={'legacy':True}) as read:
   self.assertEqual(backend.update_configuration('ep',{'ru':{}},None),{'legacy':True});read.assert_called_once()
 def test_session_preserves_dirty_drafts_and_legacy_flag(self):
  self.assertEqual(backend.session_payload({'update_dirty':True,'update_legacy':True}),{'update_dirty':True,'update_legacy':True})

class LegacyJobRoute(unittest.TestCase):
 def test_missing_metadata_resume_uses_bounded_update_not_installer_deploy(self):
  from test_app import settings
  s=settings(action='resume',ru={'host':'8.8.8.8','password':'fixture','fingerprint':'pin'},nl={'host':'9.9.9.9','password':'fixture','fingerprint':'pin'})
  calls=[]
  class Remote:
   def __init__(self,role,settings):self.role=role
   def connect(self):pass
   def close(self):pass
   def lock(self):pass
   def inventory(self):return {'managed':False,'os':{'ID':'ubuntu','VERSION_ID':'24.04'}}
   def python(self,code,data=None):
    if 'state.json' in code:return 'null'
    raise AssertionError('Unexpected installer RPC')
  job=backend.Job(s)
  with patch.object(backend,'Remote',Remote),patch.object(backend,'system_info',return_value={'os':'ubuntu','python':'3.12.3','reboot_required':False}),patch.object(legacy_update,'run',side_effect=lambda job,ru,nl:calls.append(ru.role)),patch.object(backend.engine,'deploy',side_effect=AssertionError('Must not redeploy')),patch.object(backend.engine,'install_packages',side_effect=AssertionError('Must not install')):
   backend.real_run(job)
  self.assertEqual(calls,['ru'])

class LegacyDNSUpdate(unittest.TestCase):
 def setUp(self):
  import dns_backend
  self.dns=dns_backend;self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
  self.settings={'ru':{'host':'93.184.216.34'},'nl':{'host':'9.9.9.9'},'auth':'certificate','routing':'split','vpn_port':1194,'ru_routes':[],'eu_routes':[],'update_packages':False,'update_revision':'a'*64,'legacy_confirmed':True,'dns':{'provider':'google'}}
  self.current={'config':{'auth_mode':'password','routing_mode':'split','ovpn_port':1194},'revision':'a'*64,'ru_routes':[],'eu_routes':[],'user_count':4}
  self.job=types.SimpleNamespace(settings=self.settings,report={},checkpoint=lambda:None,event=lambda *args:None)
  self.stack.enter_context(patch.object(legacy_update,'read',return_value=self.current))
  self.auth=self.stack.enter_context(patch.object(legacy_update,'call',return_value={'unchanged':False}))
  self.stack.enter_context(patch.object(backend,'collect',return_value=b'profiles'))
 def test_dns_preflight_precedes_auth_and_applies_with_fresh_revision(self):
  order=[];self.auth.side_effect=lambda *args,**kw:(order.append('auth') or {'unchanged':False})
  def execute(ep,operation,**kw):
   order.append(operation)
   if operation=='probe':return {'passed':True}
   if operation=='read':return {'revision':'b'*64}
   self.assertEqual(kw['revision'],'b'*64);self.assertEqual(kw['servers'],['8.8.8.8','8.8.4.4']);return {'servers':kw['servers']}
  with patch.object(self.dns,'execute',side_effect=execute):legacy_update.run(self.job,'ru','nl')
  self.assertEqual(order,['probe','auth','read','apply']);self.assertTrue(self.job.report['dns']['applied'])
 def test_no_dns_choice_preserves_previous_dns(self):
  self.settings.pop('dns')
  with patch.object(self.dns,'execute') as execute:legacy_update.run(self.job,'ru','nl');execute.assert_not_called()
  self.assertNotIn('dns',self.job.report)
 def test_dns_client_explicitly_clears_without_external_probe(self):
  self.settings['dns']={'provider':'unchanged'};operations=[]
  def execute(ep,operation,**kw):
   operations.append(operation)
   if operation=='read':return {'revision':'b'*64}
   self.assertEqual(kw['servers'],[]);return {'servers':[]}
  with patch.object(self.dns,'execute',side_effect=execute):legacy_update.run(self.job,'ru','nl')
  self.assertEqual(operations,['read','apply'])
 def test_failed_probe_prevents_auth_change(self):
  with patch.object(self.dns,'execute',return_value={'passed':False}),self.assertRaisesRegex(backend.UserError,'не изменены'):legacy_update.run(self.job,'ru','nl')
  self.auth.assert_not_called()
 def test_dns_failure_after_auth_is_reported_as_partial_error(self):
  def execute(ep,operation,**kw):
   if operation=='probe':return {'passed':True}
   if operation=='read':return {'revision':'b'*64}
   raise backend.UserError('Injected DNS failure')
  with patch.object(self.dns,'execute',side_effect=execute),self.assertRaisesRegex(backend.UserError,'Способ входа обновлён, а DNS требует проверки'):legacy_update.run(self.job,'ru','nl')
  self.assertIsNone(self.job.report['dns']['applied']);self.assertIn('authentication_update',self.job.report);self.assertEqual(self.job.artifact,b'profiles')

class UpdateDNSRead(unittest.TestCase):
 def test_configuration_read_includes_live_dns_without_writes_or_installer_lock(self):
  import dns_backend
  calls=[]
  class Remote:
   def __init__(self,role,settings):pass
   def connect(self):calls.append('connect')
   def python(self,code,data=None):return 'null'
   def close(self):calls.append('close')
   def lock(self):raise AssertionError('Read must not create installer lock')
  current={'legacy':True,'revision':'a'*64};dns={'provider':'google','servers':['8.8.8.8','8.8.4.4'],'consistent':True}
  with patch.object(backend,'Remote',Remote),patch.object(backend,'update_configuration',return_value=dict(current)),patch.object(dns_backend,'execute',return_value=dns) as execute:
   answer=backend.read_update_configuration({'ru':{}})
  self.assertEqual(answer['dns'],dns);self.assertEqual(answer['revision'],current['revision']);self.assertEqual(execute.call_args.args[1],'read');self.assertEqual(calls,['connect','close'])
 def test_dns_read_error_is_explicit_and_does_not_invent_client_dns(self):
  import dns_backend
  class Remote:
   def __init__(self,*args):pass
   def connect(self):pass
   def close(self):pass
   def python(self,*args):return 'null'
  with patch.object(backend,'Remote',Remote),patch.object(backend,'update_configuration',return_value={'legacy':True}),patch.object(dns_backend,'execute',side_effect=backend.UserError('DNS unavailable')):
   answer=backend.read_update_configuration({'ru':{}})
  self.assertEqual(answer['dns_error'],'DNS unavailable');self.assertNotIn('dns',answer)
