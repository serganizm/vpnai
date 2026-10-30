"""Paired archive restoration tests use fake hosts and a disposable filesystem."""
import contextlib,io,json,os,pathlib,sys,tarfile,tempfile,types,unittest,hashlib
from unittest.mock import patch,Mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import backend,backups,removal
PAIR={'ru_ip':'8.8.8.8','nl_ip':'9.9.9.9'}
PSK='a'*64
ID='20261030-120000-123456abcdef'
NAME='ovpn-backup-'+ID+'.tar.gz'
def config():return dict(PAIR,nl_host='root@9.9.9.9',ssh_port=22,ssh_key=None,initial_user='alice',vpn_net='10.77.0.0/24',tcp_net='10.79.0.0/24',gre_net='10.78.0.0/30',ovpn_port=1194,source_url='https://iplist.opencck.org/?format=json&data=cidr4',routing_mode='split',auth_mode='password')
class ArchiveFilesystem(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name);(self.root/'root').mkdir()
 def P(self,name):
  path=pathlib.Path(name)
  try:path.relative_to(self.root);return path
  except ValueError:return self.root/str(name).lstrip('/')
 def archive(self,role='ru',name=NAME,identity=ID,secret=PSK,mtime=1000,extra=None,modify=None):
  data={'var/lib/ovpn-installer/role':role+'\n','var/lib/ovpn-installer/baseline.json':json.dumps({'sysctl':{}}),'etc/swanctl/conf.d/ovpn-gre.conf':backend.engine.swan(config(),role,secret)}
  if role=='ru':
   data.update({'var/lib/ovpn-installer/state.json':json.dumps({'version':2,'complete':True,'config':config(),'psk':secret}),'etc/openvpn/server/users.json':json.dumps({'alice':{'enabled':True,'salt':'fixture','hash':'fixture'}}),'etc/openvpn/server/ru.conf':'client-connect /usr/local/libexec/ovpn-split-connect\nauth-user-pass-verify /auth.py via-file\n','etc/openvpn/server/ru-tcp.conf':'client-connect /usr/local/libexec/ovpn-split-connect\nauth-user-pass-verify /auth.py via-file\n','usr/local/sbin/ovpn-network':'fixture executable, must never run','etc/openvpn/server/tls-crypt.key':'fixture TLS key','etc/openvpn/server/pki/ca.crt':'fixture public CA','etc/openvpn/server/pki/private/ca.key':'fixture private CA','etc/openvpn/server/pki/private/ru-server.key':'fixture server key','root/ovpn-profiles/alice-UDP.ovpn':'fixture UDP','root/ovpn-profiles/alice-TCP.ovpn':'fixture TCP','root/ovpn-profiles/alice-credentials.txt':'fixture credentials','etc/ovpn-routing/force-ru.txt':'1.1.1.1/32\n'})
  owned={'/'+key:{'backup':None} for key in data}
  data['var/lib/ovpn-installer/owned.json']=json.dumps(owned)
  if identity:data['vpnai-backup.json']=json.dumps({'format':1,'id':identity,'role':role,'pair':PAIR,'created':'2026-10-30T12:00:00+00:00','configured':True})
  if modify:modify(data)
  path=self.P('/root/'+name)
  with tarfile.open(path,'w:gz') as archive:
   for filename,value in data.items():
    raw=value.encode();member=tarfile.TarInfo(filename);member.size=len(raw);member.mode=0o600;archive.addfile(member,io.BytesIO(raw))
   if extra:extra(archive)
  os.utime(path,(mtime,mtime));return path
 def execute(self,role='ru',op='list',**args):
  source=backups.REMOTE.replace('P=pathlib.Path','P=TEST_PATH');out=io.StringIO()
  with contextlib.redirect_stdout(out):exec(source,{'DATA':dict(role=role,pair=PAIR,op=op,**args),'TEST_PATH':self.P})
  return out.getvalue()
 def info(self,name=NAME,role='ru'):return json.loads(self.execute(role,'inspect',name=name))
 def test_current_manifest_inspected_without_secret_in_public_rows(self):
  self.archive();row=json.loads(self.execute())[0];self.assertTrue(row['valid']);self.assertEqual(row['snapshot_id'],ID);self.assertNotIn('state',row);self.assertNotIn(PSK,json.dumps(row))
 def test_archive_for_other_pair_rejected(self):
  self.archive(modify=lambda data:data.update({'vpnai-backup.json':json.dumps({'format':1,'id':ID,'role':'ru','pair':{}})}))
  self.assertFalse(json.loads(self.execute())[0]['valid'])
 def test_private_state_must_match_tunnel_secret(self):
  self.archive(modify=lambda data:data.update({'var/lib/ovpn-installer/state.json':json.dumps({'config':config(),'psk':'b'*64})}))
  self.assertFalse(json.loads(self.execute())[0]['valid'])
 def test_path_traversal_rejected_before_stage_creation(self):
  def extra(archive):m=tarfile.TarInfo('../../etc/shadow');m.size=1;archive.addfile(m,io.BytesIO(b'x'))
  self.archive(extra=extra)
  with self.assertRaises(SystemExit):self.execute(op='stage',name=NAME,sha256='irrelevant',stage='f'*24)
  self.assertFalse(any(self.P('/root').glob('.vpnai-restore-*')))
 def test_symbolic_link_rejected(self):
  def extra(archive):m=tarfile.TarInfo('etc/openvpn/server/pki/escape');m.type=tarfile.SYMTYPE;m.linkname='/etc/shadow';archive.addfile(m)
  self.archive(extra=extra);self.assertFalse(json.loads(self.execute())[0]['valid'])
 def test_conflicting_duplicate_rejected(self):
  def extra(archive):raw=b'other';m=tarfile.TarInfo('var/lib/ovpn-installer/role');m.size=len(raw);archive.addfile(m,io.BytesIO(raw))
  self.archive(extra=extra);self.assertFalse(json.loads(self.execute())[0]['valid'])
 def test_duplicate_members_rejected_even_if_identical(self):
  def extra(archive):raw=json.dumps({'sysctl':{}}).encode();m=tarfile.TarInfo('var/lib/ovpn-installer/baseline.json');m.size=len(raw);archive.addfile(m,io.BytesIO(raw))
  self.archive(extra=extra);self.assertFalse(json.loads(self.execute())[0]['valid'])
 def test_truncated_archive_rejected(self):
  path=self.archive();path.write_bytes(path.read_bytes()[:40]);self.assertFalse(json.loads(self.execute())[0]['valid'])
 def test_staged_data_restored_without_executables(self):
  self.archive();meta=self.info();token='f'*24
  self.execute(op='stage',name=NAME,sha256=meta['sha256'],stage=token)
  self.assertFalse(self.P('/etc/openvpn/server/users.json').exists())
  self.execute(op='apply',stage=token,sha256=meta['sha256'])
  self.assertEqual(json.loads(self.P('/etc/openvpn/server/users.json').read_text())['alice']['hash'],'fixture')
  self.assertEqual(self.P('/etc/ovpn-routing/force-ru.txt').read_text(),'1.1.1.1/32\n')
  self.assertFalse(self.P('/usr/local/sbin/ovpn-network').exists());self.assertFalse(self.P('/var/lib/ovpn-installer/owned.json').exists())
  self.execute(op='discard',stage=token);self.assertFalse(self.P('/root/.vpnai-restore-'+token).exists())
 def test_changed_archive_rejected_after_selection(self):
  self.archive();meta=self.info();self.archive(secret='b'*64)
  with self.assertRaises(SystemExit):self.execute(op='stage',name=NAME,sha256=meta['sha256'],stage='f'*24)
 def test_apply_refuses_existing_symlink_parent(self):
  if os.name=='nt':self.skipTest('Unix symlink test')
  self.archive();meta=self.info();token='f'*24;self.execute(op='stage',name=NAME,sha256=meta['sha256'],stage=token)
  parent=self.P('/etc/openvpn');parent.parent.mkdir(parents=True);outside=self.root/'outside';outside.mkdir();parent.symlink_to(outside,target_is_directory=True)
  with self.assertRaises(SystemExit):self.execute(op='apply',stage=token,sha256=meta['sha256'])
  self.assertFalse((outside/'server/users.json').exists())
 def test_old_format_is_not_offered(self):
  self.archive(identity=None);self.assertEqual(json.loads(self.execute()),[])
  with self.assertRaises(SystemExit):self.info()
 def test_metadata_contains_only_pairing_material(self):
  self.archive(role='nl');row=self.info(role='nl');self.assertIsNone(row['state']);self.assertNotIn(PSK,json.dumps(row))

class PairSelection(unittest.TestCase):
 def row(self,name='ru.tar.gz',identity=None,mtime=1000,fingerprint='same'):return {'name':name,'valid':True,'snapshot_id':identity,'mtime':mtime,'fingerprint':fingerprint,'size':10,'settings':{},'has_users':True}
 def test_new_pairs_require_same_name_id_and_secret(self):
  ru=self.row(NAME,ID);nl=self.row(NAME,ID,mtime=9000)
  selected=backups.catalogue([ru],[nl])[0];self.assertTrue(selected['available']);self.assertEqual(selected['counterpart'],NAME)
  nl['name']='other.tar.gz';self.assertFalse(backups.catalogue([ru],[nl])[0]['available'])
 def test_new_pairs_do_not_mix_matching_ids_with_different_secret(self):
  self.assertFalse(backups.catalogue([self.row(NAME,ID)],[self.row(NAME,ID,fingerprint='different')])[0]['available'])
 def test_archives_without_pair_id_rejected(self):
  self.assertFalse(backups.catalogue([self.row()],[self.row()])[0]['available'])
 def test_catalogue_does_not_expose_private_fingerprints(self):self.assertNotIn('fingerprint',backups.catalogue([self.row()],[self.row()])[0])
 def test_snapshot_has_identical_name_for_both_roles(self):
  item=backups.snapshot(PAIR);self.assertEqual(item['pair'],PAIR);self.assertTrue(backups.NAME.fullmatch(item['filename']));self.assertIn(item['id'],item['filename'])

class RestoreOrchestration(unittest.TestCase):
 def setUp(self):
  from test_app import settings
  self.settings=settings(action='resume',restore_backup=NAME,confirmed=True,initial_user='test')
  self.events=[];self.job=types.SimpleNamespace(report={},checkpoint=lambda:None,event=lambda *a:None)
  self.state={'version':2,'complete':True,'config':config(),'psk':PSK}
  events=self.events
  class EP:
   def __init__(ep,role):ep.role=role;ep.files={}
   def inventory(ep):return {'managed':False}
   def write(ep,path,text,mode=0o600,preserve=False):events.append(('write',ep.role,path));ep.files[path]=text
   def python(ep,code,data):
    if code!=backend.CLEAN_BACKUP:raise AssertionError('Unexpected mutation')
    events.append(('guard',ep.role,data['snapshot']['id']))
    return json.dumps({'configured':True,'backup':'/root/'+data['snapshot']['filename']})
   def shell(ep,*a,**kw):events.append(('rollback',ep.role));return ''
  self.ru,self.nl=EP('ru'),EP('nl')
  self.rows=({'name':NAME,'sha256':'ru-sha'},{'name':NAME,'sha256':'nl-sha'})
 def remote(self,ep,pair,operation,**data):
  self.events.append((operation,ep.role))
  if operation=='inspect':return json.dumps({'state':self.state})
  if operation=='stage':return json.dumps({'stage':data['stage'],'state':self.state if ep.role=='ru' else None})
  return 'OK'
 def run_restore(self,find=None,remote=None):
  with patch.object(backups,'find_pair',side_effect=find or (lambda *args:self.rows)),patch.object(backups,'remote',side_effect=remote or self.remote),patch.object(backend,'remove_installation',side_effect=lambda *a,**kw:self.events.append(('remove','both',kw['prepared']))),patch.object(backend.engine,'preflight',side_effect=lambda *args:self.events.append(('preflight',args[1].role))):
   return backend.restore_archive(self.job,self.settings,backend.config(self.settings),self.ru,self.nl,{'ru':{'managed':True},'nl':{'managed':True}})
 def test_both_stages_and_paired_guards_before_removal(self):
  result=self.run_restore();remove=next(i for i,e in enumerate(self.events) if e[0]=='remove')
  self.assertTrue(all(next(i for i,e in enumerate(self.events) if e[:2]==(op,role))<remove for op in ('stage','guard') for role in ('ru','nl')))
  guards=[e for e in self.events if e[0]=='guard'];self.assertEqual(guards[0][2],guards[1][2])
  self.assertEqual(result['initial_user'],'test');self.assertTrue(self.job.report['archive_restore']['data_restored'])
  saved=json.loads(self.ru.files['/var/lib/ovpn-installer/state.json']);self.assertEqual(saved['psk'],PSK);self.assertFalse(saved['complete'])
 def test_no_partner_never_changes_servers(self):
  with self.assertRaises(backend.UserError):self.run_restore(find=Mock(side_effect=backups.BackupError('No verified partner')))
  self.assertFalse(self.events)
 def test_second_stage_failure_keeps_current_configuration(self):
  def remote(ep,pair,op,**data):
   if op=='stage' and ep.role=='nl':raise backend.UserError('fixture stage failure')
   return self.remote(ep,pair,op,**data)
  with self.assertRaises(backend.UserError):self.run_restore(remote=remote)
  self.assertFalse(any(e[0] in ('guard','remove','write','rollback') for e in self.events));self.assertIn(('discard','ru'),self.events)
 def test_second_backup_failure_never_removes_current_configuration(self):
  original=self.nl.python
  self.nl.python=lambda *args:(_ for _ in ()).throw(backend.UserError('fixture backup failure'))
  with self.assertRaises(backend.UserError):self.run_restore()
  self.assertFalse(any(e[0] in ('remove','write','rollback') for e in self.events))
 def test_apply_failure_retains_safety_archive_paths(self):
  def remote(ep,pair,op,**data):
   if op=='apply' and ep.role=='nl':raise backend.UserError('fixture apply failure')
   return self.remote(ep,pair,op,**data)
  with self.assertRaises(backend.UserError):self.run_restore(remote=remote)
  self.assertIn('safety_backups',self.job.report['archive_restore']);self.assertIn('archive_restore_error',self.job.report);self.assertIn(('rollback','ru'),self.events);self.assertIn(('rollback','nl'),self.events)
 def test_restoration_requires_explicit_checkbox(self):
  from test_app import settings
  with self.assertRaises(backend.UserError):settings(action='resume',restore_backup=NAME)
 def test_arbitrary_archive_paths_rejected(self):
  from test_app import settings
  for name in ('/root/'+NAME,'../'+NAME,'ovpn-backup-a.tar.gz;id'):
   with self.subTest(name=name),self.assertRaises(backend.UserError):settings(action='resume',restore_backup=name,confirmed=True)
