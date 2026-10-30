"""Removal regression tests use a disposable filesystem and inert system commands."""
import contextlib,io,json,os,pathlib,subprocess,sys,tarfile,tempfile,types,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import backend,removal

class RemovalSandbox(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name);self.calls=[];self.foreign=False;self.missing=set();self.pair={'ru_ip':'8.8.8.8','nl_ip':'9.9.9.9'}
 def P(self,name):
  p=pathlib.Path(name)
  try:p.relative_to(self.root);return p
  except ValueError:return self.root/str(name).lstrip('/')
 def write(self,name,text):
  p=self.P(name);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text);return p
 def fixture(self,role):
  self.role=role;self.P('/root').mkdir(exist_ok=True)
  owned={'/var/lib/ovpn-installer/baseline.json':{'backup':None},'/etc/sysctl.d/90-ovpn-routing.conf':{'backup':None},'/usr/local/sbin/ovpn-network':{'backup':None},'/etc/swanctl/conf.d/ovpn-gre.conf':{'backup':None},'/usr/local/sbin/ovpn-install-rollback':{'backup':None},'/var/lib/ovpn-installer/role':{'backup':None}}
  self.write('/var/lib/ovpn-installer/owned.json',json.dumps(owned));self.write('/var/lib/ovpn-installer/role',role+'\n');self.write('/var/lib/ovpn-installer/baseline.json',json.dumps({'sysctl':{'net.ipv4.ip_forward':'0'}}))
  self.write('/usr/local/sbin/ovpn-network','#!/bin/sh\nrule filter FORWARD -i gre-nl -j ACCEPT\n');self.write('/etc/sysctl.d/90-ovpn-routing.conf','sysctl fixture\n');self.write('/etc/swanctl/conf.d/ovpn-gre.conf','fixture secret: NOT-A-REAL-KEY\n')
  self.write('/usr/local/sbin/ovpn-install-rollback',"raise RuntimeError('STALE SERVER ROLLBACK MUST NOT RUN')")
  if role=='ru':self.write('/etc/openvpn/server/pki/client.key','fixture key')
  return owned
 def which(self,name):return None if name in self.missing or name in ('nginx','ipset') else '/usr/bin/'+name
 def runner(self,args,**kw):
  self.calls.append(tuple(args))
  if args[:2]==[sys.executable,'-c']:
   # Execute only the newly supplied rollback with all paths redirected here.
   self.assertIn('role=',args[2]);self.execute(args[2],{});return types.SimpleNamespace(returncode=0,stdout='',stderr='')
  if args[0] in ('nginx','ipset'):raise AssertionError('Optional tool must not be called')
  code=1 if '-D' in args or args[:3]==('ip','link','del') else 0
  out='unrelated-ipsec: IKEv2\n' if self.foreign and args[0]=='swanctl' and '--list-conns' in args else ''
  return types.SimpleNamespace(returncode=code,stdout=out,stderr='')
 def execute(self,source,data):
  output=io.StringIO()
  with patch('subprocess.run',side_effect=self.runner),patch('shutil.which',side_effect=self.which),patch.object(os,'geteuid',return_value=0,create=True),contextlib.redirect_stdout(output):
   try:exec(source.replace('P=pathlib.Path','P=TEST_PATH'),{'DATA':data,'TEST_PATH':self.P})
   except SystemExit as error:
    if error.code not in (None,0):raise
  return output.getvalue()
 def payload(self):return {'role':self.role,'pair':self.pair}
 def backup(self):return json.loads(self.execute(removal.BACKUP,self.payload()))['backup']
 def clean(self,b):return self.execute(removal.CLEAN,dict(self.payload(),backup=b,rollback=backend.engine.ROLLBACK))
 def test_nl_removal_without_ipset_or_nginx(self):
  self.fixture('nl');self.execute(removal.PREFLIGHT,self.payload());backup=self.backup();self.clean(backup)
  self.assertFalse(self.P('/var/lib/ovpn-installer').exists());self.assertTrue(self.P('/var/lib/ovpn-installer-removal.json').is_file());self.assertTrue(pathlib.Path(backup).is_file())
  self.assertFalse(any(a[0] in ('nginx','ipset') for a in self.calls))
  self.assertFalse(any('openvpn-server@ru' in a for a in self.calls));self.assertFalse(any('310' in a for a in self.calls))
 def test_ru_cleanup_preserves_private_backup(self):
  self.fixture('ru');backup=self.backup();self.clean(backup)
  self.assertFalse(self.P('/etc/openvpn/server/pki').exists())
  if os.name!='nt':self.assertEqual(pathlib.Path(backup).stat().st_mode&0o777,0o600)
  with tarfile.open(backup) as tar:self.assertTrue(any(n.endswith('etc/swanctl/conf.d/ovpn-gre.conf') for n in tar.getnames()))
 def test_retry_after_complete_removal_is_idempotent(self):
  self.fixture('nl');backup=self.backup();self.clean(backup);before=len(self.calls)
  result=json.loads(self.execute(removal.PREFLIGHT,self.payload()));self.assertTrue(result['already_removed']);self.clean(backup);self.assertEqual(len(self.calls),before)
 def test_partial_old_removal_with_missing_network_files(self):
  self.fixture('nl');self.P('/usr/local/sbin/ovpn-network').unlink();backup=self.backup();self.clean(backup);self.assertFalse(self.P('/var/lib/ovpn-installer').exists())
 def test_missing_original_backup_stops_before_commands(self):
  owned=self.fixture('nl');owned['/etc/swanctl/conf.d/ovpn-gre.conf']['backup']='/var/lib/ovpn-installer/original/etc/swanctl/conf.d/ovpn-gre.conf';self.write('/var/lib/ovpn-installer/owned.json',json.dumps(owned))
  with self.assertRaises(SystemExit):self.execute(removal.PREFLIGHT,self.payload())
  self.assertFalse(self.calls);self.assertTrue(self.P('/etc/swanctl/conf.d/ovpn-gre.conf').exists())
 def test_role_mismatch_stops_before_commands(self):
  self.fixture('nl');data=self.payload();data['role']='ru'
  with self.assertRaises(SystemExit):self.execute(removal.PREFLIGHT,data)
  self.assertFalse(self.calls)
 def test_unowned_dangerous_path_is_rejected(self):
  owned=self.fixture('nl');owned['/etc/ssh/sshd_config']={'backup':None};self.write('/var/lib/ovpn-installer/owned.json',json.dumps(owned))
  with self.assertRaises(SystemExit):self.execute(removal.PREFLIGHT,self.payload())
  self.assertFalse(self.calls)
 def test_symlink_is_rejected_before_commands(self):
  if os.name=='nt':self.skipTest('Windows may not permit unprivileged symlinks')
  self.fixture('nl');p=self.P('/etc/swanctl/conf.d/ovpn-gre.conf');p.unlink();p.symlink_to('/unrelated')
  with self.assertRaises(SystemExit):self.execute(removal.PREFLIGHT,self.payload())
  self.assertFalse(self.calls)
 def test_missing_essential_tool_stops_before_commands(self):
  self.fixture('nl');self.missing={'iptables'}
  with self.assertRaises(SystemExit):self.execute(removal.PREFLIGHT,self.payload())
  self.assertFalse(self.calls)
 def test_receipt_for_another_pair_is_rejected(self):
  self.fixture('nl');backup=self.backup();self.clean(backup);data=self.payload();data['pair']={'ru_ip':'1.1.1.1','nl_ip':'9.9.9.9'}
  with self.assertRaises(SystemExit):self.execute(removal.PREFLIGHT,data)
 def test_foreign_ipsec_daemon_is_not_stopped(self):
  self.fixture('nl');self.foreign=True;self.clean(self.backup())
  self.assertNotIn(('systemctl','disable','--now','strongswan'),self.calls)

 def test_completed_receipt_allows_finalizing_leftover_state(self):
  self.fixture('nl');backup=self.backup();self.clean(backup);self.write('/var/lib/ovpn-installer/leftover','fixture')
  meta=json.loads(self.execute(removal.PREFLIGHT,self.payload()));self.assertTrue(meta['finalize']);before=len(self.calls);self.clean(backup)
  self.assertFalse(self.P('/var/lib/ovpn-installer').exists());self.assertEqual(len(self.calls),before)
 def test_invalid_archive_stops_before_rollback(self):
  self.fixture('ru');self.write('/root/ovpn-backup-invalid.tar.gz','not a tar archive')
  with self.assertRaises(SystemExit):self.clean(str(self.P('/root/ovpn-backup-invalid.tar.gz')))
  self.assertFalse(self.calls);self.assertTrue(self.P('/etc/openvpn/server/pki/client.key').is_file())

class RemovalPhases(unittest.TestCase):
 def make(self,fail=None,removed_nl=False):
  events=[];job=types.SimpleNamespace(report={},checkpoint=lambda:None,event=lambda *a:events.append(('event',a)))
  class EP:
   def __init__(self,role):self.role=role
   def python(self,code,data):
    stage='check' if code==removal.PREFLIGHT else 'backup' if code==removal.BACKUP else 'clean';events.append((stage,self.role))
    if fail==(stage,self.role):raise backend.UserError('fixture failure')
    if stage=='check':return json.dumps({'already_removed':removed_nl and self.role=='nl','backup':'/root/ovpn-backup-existing.tar.gz','finalize':False})
    if stage=='backup':return json.dumps({'backup':'/root/ovpn-backup-fixture.tar.gz'})
    self_test=data['rollback'];assert 'shutil.which' in self_test;return 'OK'
  return job,EP('ru'),EP('nl'),events
 def test_both_preflights_and_backups_before_any_delete(self):
  job,ru,nl,events=self.make();backend.remove_installation(job,{'ru_ip':'8.8.8.8','nl_ip':'9.9.9.9'},ru,nl)
  phases=[x for x in events if x[0]!='event'];self.assertEqual(phases,[('check','nl'),('check','ru'),('backup','nl'),('backup','ru'),('clean','nl'),('clean','ru')]);self.assertTrue(job.report['removal']['ru']['complete'])
 def test_ru_preflight_failure_does_not_delete_nl(self):
  job,ru,nl,events=self.make(fail=('check','ru'))
  with self.assertRaises(backend.UserError):backend.remove_installation(job,{'ru_ip':'8.8.8.8','nl_ip':'9.9.9.9'},ru,nl)
  self.assertFalse(any(x[0] in ('backup','clean') for x in events))
 def test_backup_failure_does_not_stop_any_services(self):
  job,ru,nl,events=self.make(fail=('backup','ru'))
  with self.assertRaises(backend.UserError):backend.remove_installation(job,{'ru_ip':'8.8.8.8','nl_ip':'9.9.9.9'},ru,nl)
  self.assertFalse(any(x[0]=='clean' for x in events))
 def test_retry_skips_nl_already_removed(self):
  job,ru,nl,events=self.make(removed_nl=True);backend.remove_installation(job,{'ru_ip':'8.8.8.8','nl_ip':'9.9.9.9'},ru,nl)
  self.assertNotIn(('clean','nl'),events);self.assertIn(('clean','ru'),events)

 def test_partial_failure_records_successful_nl_removal(self):
  job,ru,nl,events=self.make(fail=('clean','ru'))
  with self.assertRaisesRegex(backend.UserError,'повторный запуск'):backend.remove_installation(job,{'ru_ip':'8.8.8.8','nl_ip':'9.9.9.9'},ru,nl)
  self.assertTrue(job.report['removal']['nl']['complete']);self.assertFalse(job.report['removal']['ru'].get('complete',False))
