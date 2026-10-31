import importlib.util,json,pathlib,sys,tempfile,types,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import backend,dns_backend,dns_policy as policy,dns_remote as remote

class DNSValidation(unittest.TestCase):
 def test_public_only_and_presets(self):
  self.assertEqual(dns_backend.validate({'provider':'google'})['servers'],['8.8.8.8','8.8.4.4'])
  for address in ['127.0.0.1','10.0.0.1','169.254.169.254','::1','1.1.1.1; reboot','0.0.0.0']:
   with self.subTest(address=address),self.assertRaises(backend.UserError):dns_backend.validate({'provider':'custom','servers':[address]})
  with self.assertRaises(backend.UserError):dns_backend.validate({'provider':'custom','servers':['1.1.1.1','1.1.1.1']})
 def test_apply_requires_confirmation_revision_and_live_probe(self):
  settings={'ru':{'host':'8.8.4.4'},'nl':{'host':'9.9.9.9'}}
  data={'provider':'cloudflare','revision':'a'*64}
  with patch.object(dns_backend,'remote') as call:
   with self.assertRaises(backend.UserError):dns_backend.dispatch(settings,'dns-apply',data)
   call.assert_not_called()
  with patch.object(dns_backend,'remote',return_value={'passed':False}) as call:
   with self.assertRaises(backend.UserError):dns_backend.dispatch(settings,'dns-apply',dict(data,confirmed=True))
   self.assertEqual(call.call_args.args[1:3],('nl','probe'));self.assertEqual(call.call_count,1)
 def test_dns_session_and_operation_validation(self):
  choice={'provider':'custom','servers':['9.9.9.9']}
  self.assertEqual(backend.session_payload({'dns':choice})['dns'],choice)
  from test_app import settings
  self.assertEqual(settings(dns=choice)['dns'],choice)

class DNSTransaction(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.base=pathlib.Path(self.temp.name);self.stack=__import__('contextlib').ExitStack();self.addCleanup(self.stack.close);self.addCleanup(self.temp.cleanup)
  self.conf=[str(self.base/'ru.conf'),str(self.base/'ru-tcp.conf')];self.state=str(self.base/'dns.json');self.helper=str(self.base/'helper');self.unit=str(self.base/'unit');self.owner=str(self.base/'owned.json');self.dropins=[str(self.base/'udp.dropin'),str(self.base/'tcp.dropin')]
  for key,value in [('CONF',self.conf),('STATE',self.state),('HELPER',self.helper),('UNIT',self.unit),('OWNER',self.owner),('DROPINS',self.dropins)]:self.stack.enter_context(patch.object(remote,key,value))
  # Redirect only backup location into the isolated fixture.
  original_path=pathlib.Path
  def safe_path(value):return original_path(self.base/'backups') if str(value)=='/root/ovpn-dns-backups' else original_path(value)
  self.stack.enter_context(patch.object(remote,'pathlib',types.SimpleNamespace(Path=safe_path)))
  for i,p in enumerate(self.conf):pathlib.Path(p).write_text('dev tun-test\nserver '+('10.77.0.0' if i==0 else '10.79.0.0')+' 255.255.255.0\npush "route 9.0.0.0 255.0.0.0"\npush "dhcp-option DNS 8.8.8.8"\n<key>\nDO-NOT-EXPOSE\n</key>\n')
  pathlib.Path(self.owner).write_text('{}')
  self.kernel_rules=[{'priority':0,'src':'all','table':'local'}];self.routes=[];self.commands=[];self.fail=False;self.enabled=False
  self.active={'openvpn-server@ru.service':True,'openvpn-server@ru-tcp.service':True,'ovpn-dns.service':False}
  self.stack.enter_context(patch.object(policy,'run',self.execute_command));self.stack.enter_context(patch.object(remote,'command',self.execute_command))
  for key in ['TABLE','PRIORITY','inspect','rules','apply','rule_key']:self.stack.enter_context(patch.object(remote,key,getattr(policy,key),create=True))
 def execute_command(self,args,check=True):
  self.commands.append(args);code=0;out=''
  if args[:4]==['ip','-j','rule','show']:out=json.dumps(self.kernel_rules)
  elif args[:4]==['ip','-j','-d','link']:out=json.dumps([{'ifname':'gre-nl','flags':['UP'],'linkinfo':{'info_kind':'gre','info_data':{'remote':'9.9.9.9'}}}])
  elif args[:4]==['ip','-j','route','show']:out=json.dumps([{'dst':'default','gateway':'10.78.0.2','dev':'gre-nl'}] if args[-1]=='310' else self.routes)
  elif args[:3]==['ip','route','flush']:
   if 'table' in args:self.routes=[]
  elif args[:3]==['ip','route','replace']:
   if 'unreachable' in args:self.routes.append({'dst':'default','type':'unreachable'})
   else:self.routes.append({'dst':'default','gateway':args[args.index('via')+1],'dev':args[args.index('dev')+1]})
  elif args[:3]==['ip','rule','add']:
   net=__import__('ipaddress').ip_network(args[args.index('from')+1]);destination=__import__('ipaddress').ip_network(args[args.index('to')+1]);self.kernel_rules.append({'priority':int(args[args.index('priority')+1]),'src':str(net.network_address),'srclen':net.prefixlen,'dst':str(destination.network_address),'table':int(args[-1])})
  elif args[:3]==['ip','rule','del']:
   self.kernel_rules.remove(next(r for r in self.kernel_rules if r.get('priority')==policy.PRIORITY and policy.rule_key(r)==(args[args.index('from')+1],args[args.index('to')+1],int(args[-1]))))
  elif args[0]=='swanctl':out="ovpn-gre: #1, ESTABLISHED\n  remote @ 9.9.9.9\n  gre: #1, INSTALLED\n"
  elif args[0]=='iptables':pass
  elif args[0]=='systemctl':
   operation=args[1]
   if operation=='is-enabled':code=0 if self.enabled else 1
   elif operation=='is-active':code=0 if self.active.get(args[-1],False) else 3;out='active' if code==0 else 'inactive'
   elif operation in ('enable','disable'):self.enabled=operation=='enable'
   elif operation=='stop':
    for name in args[2:]:self.active[name]=False
   elif operation=='restart':
    if self.fail and 'openvpn-server@ru.service' in args:self.fail=False;code=1
    else:
     for name in args[2:]:
      self.active[name]=True
      if name=='ovpn-dns.service' and pathlib.Path(self.state).exists():policy.apply(json.loads(pathlib.Path(self.state).read_text()))
  else:raise AssertionError(args)
  if check and code:raise ValueError('Injected service failure')
  return types.SimpleNamespace(returncode=code,stdout=out)
 def data(self,provider='cloudflare',servers=None):
  return {'provider':provider,'servers':['1.1.1.1','1.0.0.1'] if servers is None else servers,'revision':remote.status()['revision'],'peer':'9.9.9.9','helper':'# helper\n','unit':'[Unit]\n'}
 def test_empty_standard_ipsec_table_allows_apply_read_and_clear(self):
  rule={'priority':220,'src':'all','table':'220'};self.kernel_rules.append(rule)
  original=self.execute_command
  def command(args,check=True):
   if args==['ip','-j','route','show','table','220']:return types.SimpleNamespace(returncode=2,stdout='[]',stderr='Error: ipv4: FIB table does not exist.')
   return original(args,check)
  with patch.object(policy,'run',command):
   answer=remote.configure(self.data('google',['8.8.8.8','8.8.4.4']))
   self.assertEqual(answer['provider'],'google');self.assertTrue(answer['policy_ready'])
   self.assertEqual(remote.status()['servers'],['8.8.8.8','8.8.4.4'])
   remote.configure(self.data('unchanged',[]))
  self.assertIn(rule,self.kernel_rules);self.assertEqual(len(self.kernel_rules),2)
 def test_populated_ipsec_table_still_refused_without_writes(self):
  self.kernel_rules.append({'priority':220,'src':'all','table':'220'});before=remote.snapshot();original=self.execute_command
  def command(args,check=True):
   if args==['ip','-j','route','show','table','220']:return types.SimpleNamespace(returncode=0,stdout='[{"dst":"default","dev":"other"}]')
   return original(args,check)
  with patch.object(policy,'run',command),self.assertRaisesRegex(ValueError,'Более ранние'):remote.configure(self.data())
  self.assertEqual(remote.snapshot(),before);self.assertFalse(self.base.joinpath('backups').exists())
 def test_nonstandard_early_rule_still_refused(self):
  self.kernel_rules.append({'priority':220,'src':'all','table':'220','fwmark':'0x1'})
  before=remote.snapshot()
  with self.assertRaisesRegex(ValueError,'Более ранние'):remote.configure(self.data())
  self.assertEqual(remote.snapshot(),before)
 def test_linux_rule_prefix_formats(self):
  self.assertEqual(policy.rule_key({'priority':10220,'src':'10.77.0.0','srclen':24,'dst':'8.8.8.8','table':'31220'}),('10.77.0.0/24','8.8.8.8/32',31220))
  self.assertEqual(policy.rule_key({'src':'10.77.0.0/24','dst':'8.8.8.8/32','table':31220}),('10.77.0.0/24','8.8.8.8/32',31220))
 def make_orphan(self):
  import base64
  answer=remote.configure(self.data());receipt=json.loads(pathlib.Path(answer['backup'],'files.json').read_text())
  for path,entry in receipt.items():
   if entry['body'] is None:pathlib.Path(path).unlink(missing_ok=True)
   else:pathlib.Path(path).write_bytes(base64.b64decode(entry['body']))
  self.enabled=False;self.active['ovpn-dns.service']=False
 def test_proven_orphan_recovered_only_during_confirmed_transaction(self):
  self.make_orphan();self.assertTrue(remote.status()['incomplete']);self.assertIsNone(remote.snapshot()[self.state]);self.assertEqual(len(self.kernel_rules),5)
  answer=remote.configure(self.data('google',['8.8.8.8','8.8.4.4']))
  self.assertEqual(answer['servers'],['8.8.8.8','8.8.4.4']);self.assertTrue(answer['policy_ready']);self.assertEqual(len(self.kernel_rules),5)
  remote.configure(self.data('unchanged',[]));self.assertEqual(len(self.kernel_rules),1)
 def test_orphan_without_exact_backup_proof_is_refused(self):
  self.make_orphan();pathlib.Path(self.conf[0]).write_text(pathlib.Path(self.conf[0]).read_text()+'# changed outside app\n');before=remote.snapshot();rules=list(self.kernel_rules)
  with self.assertRaisesRegex(ValueError,'Ресурсы'):remote.configure(self.data())
  self.assertEqual(remote.snapshot(),before);self.assertEqual(self.kernel_rules,rules)
 def test_dns_unit_failure_removes_linux_format_rules_and_allows_retry(self):
  original=self.execute_command;failed=False;before=remote.snapshot()
  def command(args,check=True):
   nonlocal failed
   if args==['systemctl','restart','ovpn-dns.service'] and not failed:
    failed=True;raise ValueError('Injected DNS unit failure')
   return original(args,check)
  with patch.object(remote,'command',command),self.assertRaisesRegex(ValueError,'прежние настройки восстановлены'):remote.configure(self.data())
  self.assertEqual(remote.snapshot(),before);self.assertEqual(len(self.kernel_rules),1);self.assertFalse(self.routes)
  self.assertTrue(remote.configure(self.data())['policy_ready'])
 def test_apply_both_profiles_and_clear_preserves_other_settings(self):
  answer=remote.configure(self.data());self.assertTrue(answer['policy_ready']);self.assertTrue(self.enabled)
  for path in self.conf:
   text=pathlib.Path(path).read_text();self.assertEqual(text.count('dhcp-option DNS'),2);self.assertIn('push "route 1.1.1.1 255.255.255.255"',text);self.assertIn('DO-NOT-EXPOSE',text);self.assertIn('route 9.0.0.0',text)
  self.assertEqual(len(self.kernel_rules),5)
  remote.configure(self.data());self.assertEqual(len(self.kernel_rules),5)
  remote.configure(self.data('unchanged',[]));self.assertEqual(len(self.kernel_rules),1);self.assertFalse(self.routes)
  self.assertTrue(all('dhcp-option DNS' not in pathlib.Path(p).read_text() for p in self.conf))
 def test_stale_revision_and_foreign_routes_refused_before_writes(self):
  data=self.data();pathlib.Path(self.conf[0]).write_text(pathlib.Path(self.conf[0]).read_text()+'# changed\n')
  before=remote.snapshot()
  with self.assertRaisesRegex(ValueError,'изменились'):remote.configure(data)
  self.assertEqual(remote.snapshot(),before);self.assertFalse(self.base.joinpath('backups').exists())
  self.routes=[{'dst':'default','gateway':'2.2.2.2','dev':'other'}]
  with self.assertRaises(ValueError):remote.configure(self.data())
  self.assertEqual(remote.snapshot(),before)
 def test_service_failure_restores_exact_files_and_old_vpn(self):
  before=remote.snapshot();self.fail=True
  with self.assertRaisesRegex(ValueError,'прежние настройки восстановлены'):remote.configure(self.data())
  self.assertEqual(remote.snapshot(),before);self.assertEqual(len(self.kernel_rules),1);self.assertFalse(self.routes)
  self.assertTrue(self.active['openvpn-server@ru.service']);self.assertTrue(self.base.joinpath('backups').exists())
 def test_existing_dns_state_reapplies_policy_after_restart(self):
  remote.configure(self.data());config=json.loads(pathlib.Path(self.state).read_text());self.kernel_rules=self.kernel_rules[:1];self.routes=[]
  self.assertFalse(remote.status()['policy_ready']);policy.apply(config);self.assertTrue(remote.status()['policy_ready'])

 def test_inactive_tcp_service_is_not_started(self):
  self.active['openvpn-server@ru-tcp.service']=False
  remote.configure(self.data())
  self.assertTrue(self.active['openvpn-server@ru.service']);self.assertFalse(self.active['openvpn-server@ru-tcp.service'])
 def test_missing_ipsec_is_refused_without_changing_files(self):
  original=self.execute_command
  def command(args,check=True):
   if args[0]=='swanctl':return types.SimpleNamespace(returncode=0,stdout='')
   return original(args,check)
  before=remote.snapshot()
  with patch.object(remote,'command',command),self.assertRaisesRegex(ValueError,'GRE/IPsec'):remote.configure(self.data())
  self.assertEqual(remote.snapshot(),before);self.assertFalse(self.base.joinpath('backups').exists())

class DNSBootGuard(unittest.TestCase):
 def test_missing_state_blocks_enabled_dns_but_allows_factory_configuration(self):
  with tempfile.TemporaryDirectory() as folder:
   root=pathlib.Path(folder);configs=root/'server';configs.mkdir();profile=configs/'ru.conf'
   script=pathlib.Path(policy.__file__).read_text().replace('/etc/ovpn-routing/dns.json',(root/'missing.json').as_posix()).replace('/etc/openvpn/server',configs.as_posix())
   profile.write_text('server 10.77.0.0 255.255.255.0\n')
   with patch('subprocess.run',side_effect=AssertionError('No network changes on factory boot')):exec(script,{'__name__':'__main__'})
   profile.write_text('# VPNAI DNS BEGIN\npush "dhcp-option DNS 1.1.1.1"\n')
   with self.assertRaises(SystemExit):exec(script,{'__name__':'__main__'})

class DNSPreservation(unittest.TestCase):
 def test_existing_manual_dns_is_preserved_without_enabling_new_policy(self):
  import contextlib,io
  with tempfile.TemporaryDirectory() as folder:
   root=pathlib.Path(folder);server=root/'server';server.mkdir()
   for name in ('ru','ru-tcp'):(server/(name+'.conf')).write_text('server 10.77.0.0 255.255.255.0\npush "dhcp-option DNS 10.0.0.53"\n')
   capture=dns_backend.CAPTURE.replace('/etc/openvpn/server',server.as_posix()).replace('/etc/ovpn-routing/dns.json',(root/'missing.json').as_posix())
   output=io.StringIO()
   with contextlib.redirect_stdout(output):exec(capture,{})
   value=json.loads(output.getvalue());self.assertFalse(value['managed'])
   for name in ('ru','ru-tcp'):(server/(name+'.conf')).write_text('server 10.77.0.0 255.255.255.0\n')
   restore=dns_backend.RESTORE_PUSH.replace('/etc/openvpn/server',server.as_posix())
   with contextlib.redirect_stdout(io.StringIO()):exec(restore,{'DATA':value})
   for name in ('ru','ru-tcp'):
    text=(server/(name+'.conf')).read_text();self.assertIn('dhcp-option DNS 10.0.0.53',text);self.assertNotIn('VPNAI DNS BEGIN',text)
