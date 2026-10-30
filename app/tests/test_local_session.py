import ast,builtins,contextlib,http.client,io,json,os,pathlib,subprocess,sys,tempfile,threading,time,types,unittest,zipfile
from unittest.mock import patch,Mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import app,backend
from ssh_trust import TrustStore
class SessionAPI(unittest.TestCase):
 def setUp(self):
  self.application=app.Application();self.server=app.Server(('127.0.0.1',0),self.application);self.worker=threading.Thread(target=self.server.serve_forever,daemon=True);self.worker.start()
 def tearDown(self):self.server.shutdown();self.server.server_close();self.application.close()
 def request(self,path,data=None,token=None):
  headers={'X-Local-Token':token or self.application.token};body=None
  if data is not None:headers['Content-Type']='application/json';body=json.dumps(data)
  connection=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=5);connection.request('POST' if data is not None else 'GET',path,body,headers);response=connection.getresponse();result=(response.status,json.loads(response.read()));connection.close();return result
 def test_memory_session_round_trip_and_new_process_empty(self):
  payload={'ru':{'host':'8.8.8.8','password':'PRIVATE-FIXTURE'},'nl':{'host':'9.9.9.9','password':'OTHER-FIXTURE'},'initial_user':'test','confirmed':True,'fingerprint':'ignored'}
  self.assertEqual(self.request('/api/session',payload)[0],200)
  stored=self.request('/api/session')[1];self.assertEqual(stored['ru']['password'],'PRIVATE-FIXTURE');self.assertNotIn('confirmed',stored);self.assertNotIn('fingerprint',stored)
  self.assertEqual(app.Application().session,{})
 def test_session_requires_authorization(self):
  self.assertEqual(self.request('/api/session',token='wrong')[0],403);self.assertEqual(self.request('/api/session',{'ru':{'password':'secret'}},token='wrong')[0],403);self.assertEqual(self.application.session,{})
 def test_exit_clears_credentials_and_ssh_trust(self):
  self.request('/api/session',{'ru':{'host':'8.8.8.8','password':'PRIVATE-FIXTURE'}})
  self.application.trust.memory={'8.8.8.8:22':'SHA256:'+'A'*43}
  self.assertEqual(self.request('/api/exit',{})[0],200);self.worker.join(3);self.assertEqual(self.application.session,{});self.assertEqual(self.application.trust.read(),{})
 def test_demo_api_cannot_start_any_operation(self):
  with patch.object(backend,'fingerprints',side_effect=AssertionError('No SSH')):
   self.assertEqual(self.request('/api/jobs',{'demo':True})[0],400)
  self.assertFalse(self.application.jobs)
 def test_checkbox_requires_boolean_true(self):
  from test_app import settings
  for bad in (False,None,1,'true','УДАЛИТЬ'):
   with self.subTest(bad=bad),self.assertRaises(backend.UserError):settings(action='fresh',confirmed=bad)
  self.assertEqual(settings(action='fresh',confirmed=True)['action'],'fresh')
 def test_default_trust_never_writes_to_disk(self):
  store=self.application.trust;self.assertIsNone(store.path)
  settings={'ru':{'host':'8.8.8.8','port':22},'nl':{'host':'9.9.9.9','port':22}}
  pins={'ru':'SHA256:'+'A'*43,'nl':'SHA256:'+'B'*43}
  with patch('ssh_trust.tempfile.NamedTemporaryFile',side_effect=AssertionError('No disk writes')):
   pending=store.prepare(settings,pins);store.confirm(pending['confirmation_token'])
  self.assertEqual(store.trusted(settings),pins);self.assertEqual(TrustStore(persistent=False).read(),{})

 def test_backup_catalogue_authorized_and_read_only(self):
  request={'ru':{'host':'8.8.8.8','password':'fixture'},'nl':{'host':'9.9.9.9','password':'fixture'}}
  with patch.object(self.application.trust,'trusted',return_value={'ru':'pin','nl':'pin'}),patch.object(backend,'available_backups',return_value=[]) as catalogue:
   self.assertEqual(self.request('/api/backups',request)[0],200);catalogue.assert_called_once()
  self.assertFalse(self.application.jobs)
 def test_backup_catalogue_rejects_unauthorized_access_before_ssh(self):
  with patch.object(backend,'available_backups',side_effect=AssertionError('No SSH')):self.assertEqual(self.request('/api/backups',{},token='wrong')[0],403)

class InitialUser(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.db=pathlib.Path(self.temp.name)/'users.json';self.db.write_text(json.dumps({'user1':{'enabled':True}}))
 def execute(self,name,record=None,code=0):
  if record is not None:self.db.write_text(json.dumps({name:record}))
  def run(args,**kwargs):
   if code==0:
    data=json.loads(self.db.read_text());data[args[-1]]={'enabled':True};self.db.write_text(json.dumps(data))
   return types.SimpleNamespace(returncode=code)
  source=backend.engine.INITIAL_USER.replace("'/etc/openvpn/server/users.json'",repr(str(self.db)))
  output=io.StringIO()
  with patch('subprocess.run',side_effect=run) as call,contextlib.redirect_stdout(output):exec(source,{'DATA':name})
  return json.loads(output.getvalue()),call
 def test_requested_user_created_without_removing_saved_user(self):
  result,call=self.execute('test');self.assertEqual(result,{'name':'test','created':True,'active':True});self.assertIn('user1',json.loads(self.db.read_text()));call.assert_called_once()
 def test_active_user_keeps_password(self):
  result,call=self.execute('test',{'enabled':True,'password':'fixture-hash'});self.assertFalse(result['created']);call.assert_not_called();self.assertEqual(json.loads(self.db.read_text())['test']['password'],'fixture-hash')
 def test_disabled_name_is_not_silently_reactivated(self):
  with self.assertRaises(SystemExit):self.execute('test',{'enabled':False})
 def test_creation_failure_does_not_report_success(self):
  with self.assertRaises(SystemExit):self.execute('test',code=1)

class MenuExport(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name)
  (self.root/'root').mkdir();self.out=self.root/'profiles';self.out.mkdir()
  for user in ('alice','bob'):
   for suffix in ('.ovpn','-UDP.ovpn','-TCP.ovpn','-credentials.txt'):(self.out/(user+suffix)).write_text('fixture '+suffix)
 def P(self,name):
  path=pathlib.Path(name)
  try:path.relative_to(self.root);return path
  except ValueError:return self.root/str(name).lstrip('/')
 def open(self,name,*args,**kwargs):
  path=self.P(name);path.parent.mkdir(parents=True,exist_ok=True);return builtins.open(path,*args,**kwargs)
 def prepare(self,all_users=False):
  source=(backend.engine.ROOT/'payload/ru/usr/local/libexec/ovpn-menu.py').read_text();tree=ast.parse(source)
  nodes=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in ('download_candidates','prepare_download')]
  ns={'pathlib':types.SimpleNamespace(Path=self.P),'OUT':self.out,'users':lambda:{'alice':{'enabled':True},'bob':{'enabled':True}},'os':os,'open':self.open}
  exec(compile(ast.Module(body=nodes,type_ignores=[]),'menu-export','exec'),ns)
  with patch.dict(sys.modules,{'fcntl':types.SimpleNamespace(LOCK_SH=1,flock=lambda *args:None)}):return ns['prepare_download'](['alice'],all_users)
 def test_single_archive_name_and_contents(self):
  path,count=self.prepare();self.assertEqual(path.name,'openvpn-alice.zip');self.assertEqual(count,1)
  with zipfile.ZipFile(path) as archive:self.assertEqual(set(archive.namelist()),{'alice-UDP.ovpn','alice-TCP.ovpn','alice-credentials.txt'})
 def test_all_archive_name_and_count(self):
  path,count=self.prepare(True);self.assertEqual(path.name,'openvpn-all.zip');self.assertEqual(count,2)
 def test_link_and_scp_use_same_universal_archive_names(self):
  source=(backend.engine.ROOT/'payload/ru/usr/local/sbin/ovpn-link').read_text();self.assertIn("'openvpn-'+name+'.zip'",source)
  for path in (backend.engine.ROOT/'payload').rglob('*'):
   if path.is_file():self.assertNotIn('IPSRU',path.read_text())
