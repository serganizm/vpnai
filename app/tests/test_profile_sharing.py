import contextlib,json,pathlib,sys,tempfile,time,types,unittest,os,threading,urllib.request,urllib.error
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import admin_backend,backend
class LinkAPI(unittest.TestCase):
 def test_tokens_are_reused_separately_and_cleared_with_session(self):
  app=types.SimpleNamespace(lock=threading.RLock(),jobs={},stopping=False)
  service=admin_backend.AdminService(app);service.settings={'ru':{'host':'8.8.8.8'},'nl':{}}
  calls=[]
  def remote(role,op,**data):
   calls.append(data);return {'token':data['protocol']+'-token','url':'https://8.8.8.8/d/test/profile.ovpn','expires':1600}
  service.remote=remote
  service.dispatch('profile-link',{'name':'alice','protocol':'udp'});service.dispatch('profile-link',{'name':'alice','protocol':'tcp'});result=service.dispatch('profile-link',{'name':'alice','protocol':'udp'})
  self.assertEqual(calls[0]['token'],'');self.assertEqual(calls[1]['token'],'');self.assertEqual(calls[2]['token'],'udp-token');self.assertNotIn('token',result)
  service.close();self.assertEqual(service.share_links,{})
 def test_invalid_protocol_never_reaches_ssh(self):
  app=types.SimpleNamespace(lock=threading.RLock(),jobs={},stopping=False);service=admin_backend.AdminService(app);service.settings={'ru':{'host':'8.8.8.8'}}
  service.remote=lambda *a,**kw:self.fail('Unexpected SSH')
  with self.assertRaises(backend.UserError):service.dispatch('profile-link',{'name':'alice','protocol':'../../secret'})
@unittest.skipIf(sys.platform=='win32','Linux link storage integration uses flock and group ownership')
class LinkStorage(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name);self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close);self.clock=1000
  for name in ('base','profiles','links','run'):(self.root/name).mkdir()
  (self.root/'base/users.json').write_text(json.dumps({'alice':{'enabled':True}}))
  for proto in ('UDP','TCP'):(self.root/'profiles'/('alice-'+proto+'.ovpn')).write_text('client\nproto '+proto.lower()+'\n')
  code=(ROOT/'admin_remote.py').read_text()
  for before,after in [('/etc/openvpn/server','base'),('/root/ovpn-profiles','profiles'),('/var/lib/ovpn-links','links'),('/run/ovpn-user.lock','run/user.lock'),('/run/ovpn-links.lock','run/links.lock')]:code=code.replace(before,(self.root/after).as_posix())
  self.namespace={};exec(compile(code,'remote-fixture','exec'),self.namespace)
  import grp
  self.stack.enter_context(patch.object(grp,'getgrnam',return_value=types.SimpleNamespace(gr_gid=os.getgid())))
  self.stack.enter_context(patch.object(os,'fchown',return_value=None));self.stack.enter_context(patch.object(time,'time',side_effect=lambda:self.clock))
 def create(self,protocol='udp',token=''):
  return self.namespace['execute']({'operation':'profile-link','name':'alice','protocol':protocol,'token':token,'public_host':'8.8.8.8'})
 def test_same_link_reused_until_ten_minutes(self):
  first=self.create();self.clock=1200;second=self.create(token=first['token']);self.assertEqual(first['url'],second['url']);self.assertEqual(second['expires'],1600);self.assertEqual(len(list((self.root/'links').glob('*.json'))),1)
 def test_udp_tcp_are_independent_and_expired_link_is_replaced(self):
  udp=self.create();self.clock=1100;tcp=self.create('tcp');self.assertNotEqual(udp['url'],tcp['url']);self.assertEqual(tcp['expires'],1700)
  self.clock=1600;new=self.create(token=udp['token']);self.assertNotEqual(new['url'],udp['url']);self.assertEqual(new['expires'],2200)
 def test_changed_profile_and_revoked_token_never_reuse_stale_payload(self):
  first=self.create();(self.root/'profiles/alice-UDP.ovpn').write_text('new configuration')
  second=self.create(token=first['token']);self.assertNotEqual(first['url'],second['url'])
  for file in (self.root/'links').glob('*.json'):file.unlink()
  third=self.create(token=second['token']);self.assertNotEqual(second['url'],third['url'])
 def test_disabled_and_symlinked_profiles_are_rejected(self):
  (self.root/'profiles/alice-UDP.ovpn').unlink();(self.root/'profiles/alice-UDP.ovpn').symlink_to(self.root/'base/users.json')
  with self.assertRaises(ValueError):self.create()
  (self.root/'base/users.json').write_text(json.dumps({'alice':{'enabled':False}}))
  with self.assertRaises(ValueError):self.create('tcp')
 def test_existing_https_handler_serves_exact_file_and_expires(self):
  result=self.create();code=(ROOT/'core/payload/ru/usr/local/libexec/ovpn-link-server.py').read_text().replace('/var/lib/ovpn-links',(self.root/'links').as_posix());code=code[:code.rindex("Server(('127.0.0.1',8765)")];namespace={};exec(code,namespace)
  server=namespace['Server'](('127.0.0.1',0),namespace['Handler']);worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
  try:
   path=urllib.parse.urlsplit(result['url']).path;url='http://127.0.0.1:'+str(server.server_port)+path
   with urllib.request.urlopen(url) as response:
    self.assertEqual(response.read(),b'client\nproto udp\n');self.assertIn('alice-UDP.ovpn',response.headers['Content-Disposition'])
   self.clock=1600
   with self.assertRaises(urllib.error.HTTPError) as error:urllib.request.urlopen(url)
   self.assertEqual(error.exception.code,410)
  finally:server.shutdown();server.server_close();worker.join()
