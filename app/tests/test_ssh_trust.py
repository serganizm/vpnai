"""Automatic first-use SSH trust and fail-closed pinning; no external network."""
import contextlib,http.client,json,os,pathlib,socket,sys,tempfile,threading,types,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import app,backend
from ssh_trust import TrustStore

def data():return {'demo':False,'action':'verify','ru':{'host':'8.8.8.8','port':22,'password':'PRIVATE-RU'},'nl':{'host':'9.9.9.9','port':2222,'password':'PRIVATE-NL'}}
def pins():return {'ru':'SHA256:'+'A'*43,'nl':'SHA256:'+'B'*43}

class SSHTrust(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.path=pathlib.Path(self.temp.name)/'data'/'ssh-hosts.json';self.store=TrustStore(self.path);self.settings=backend.validate(data())
 def accept(self):
  p=self.store.prepare(self.settings,pins());self.store.confirm(p['confirmation_token']);return p
 def test_prepare_does_not_save_keys_or_credentials(self):
  result=self.store.prepare(self.settings,pins());self.assertTrue(result['confirmation_required']);self.assertFalse(self.path.exists())
  self.assertNotIn('PRIVATE-',json.dumps(self.store.pending));self.assertNotIn('PRIVATE-',json.dumps(result))
 def test_confirm_persists_and_survives_restart(self):
  self.accept();other=TrustStore(self.path);result=other.prepare(self.settings,pins())
  self.assertFalse(result['confirmation_required']);self.assertEqual(other.trusted(self.settings),pins());self.assertNotIn('PRIVATE-',self.path.read_text())
 def test_changed_key_rejected_without_overwriting(self):
  self.accept();before=self.path.read_bytes()
  with self.assertRaisesRegex(backend.UserError,'ключ изменился'):self.store.prepare(self.settings,dict(pins(),ru='SHA256:'+'C'*43))
  self.assertEqual(self.path.read_bytes(),before)
 def test_new_ru_and_changed_nl_do_not_partially_save(self):
  self.accept();before=self.path.read_bytes();self.settings['ru']['port']=2200
  with self.assertRaises(backend.UserError):self.store.prepare(self.settings,dict(pins(),nl='SHA256:'+'C'*43))
  self.assertEqual(self.path.read_bytes(),before)
 def test_confirmation_expires(self):
  p=self.store.prepare(self.settings,pins());self.store.pending[p['confirmation_token']]['expires']=0
  with self.assertRaisesRegex(backend.UserError,'истекло'):self.store.confirm(p['confirmation_token'])
  self.assertFalse(self.path.exists())
 def test_unknown_confirmation_and_replay_rejected(self):
  with self.assertRaises(backend.UserError):self.store.confirm('unissued')
  p=self.accept()
  with self.assertRaises(backend.UserError):self.store.confirm(p['confirmation_token'])
 def test_stale_confirmation_cannot_replace_newly_trusted_key(self):
  first=self.store.prepare(self.settings,pins());second=self.store.prepare(self.settings,dict(pins(),ru='SHA256:'+'C'*43));self.store.confirm(second['confirmation_token'])
  with self.assertRaisesRegex(backend.UserError,'изменён'):self.store.confirm(first['confirmation_token'])
  self.assertEqual(self.store.read()['8.8.8.8:22'],'SHA256:'+'C'*43)
 def test_corrupt_database_fails_closed(self):
  self.path.parent.mkdir();self.path.write_text('{')
  with self.assertRaisesRegex(backend.UserError,'базу SSH'):self.store.prepare(self.settings,pins())
  self.assertEqual(self.path.read_text(),'{')
 def test_invalid_pin_rejected(self):
  with self.assertRaises(backend.UserError):self.store.prepare(self.settings,dict(pins(),ru='invalid'))
 def test_real_job_without_trust_cannot_start(self):
  application=app.Application(self.path)
  with patch.object(backend,'Job',side_effect=AssertionError('must not start')),self.assertRaises(backend.UserError):application.start(data())
 def test_prepared_but_unconfirmed_job_cannot_start(self):
  application=app.Application(self.path);application.trust.prepare(self.settings,pins());d=data()
  for role in ('ru','nl'):d[role]['fingerprint']=pins()[role]
  with self.assertRaises(backend.UserError):application.start(d)
  self.assertEqual(application.jobs,{})
 def test_job_uses_trusted_pins_and_rejects_client_override(self):
  self.accept();application=app.Application(self.path)
  with patch.object(threading.Thread,'start'):job=application.start(data())
  self.assertEqual({r:job.settings[r]['fingerprint'] for r in ('ru','nl')},pins())
  bad=data();bad['ru']['fingerprint']='SHA256:'+'C'*43
  with self.assertRaisesRegex(backend.UserError,'отличается'):app.Application(self.path).start(bad)
 def test_permissions_and_no_partial_write_on_failure(self):
  self.accept()
  if os.name!='nt':self.assertEqual(self.path.stat().st_mode&0o777,0o600)
  before=self.path.read_bytes();self.settings['ru']['port']=2200;p=self.store.prepare(self.settings,pins())
  with patch('ssh_trust.os.replace',side_effect=OSError()),self.assertRaises(backend.UserError):self.store.confirm(p['confirmation_token'])
  self.assertEqual(before,self.path.read_bytes());self.assertFalse(list(self.path.parent.glob('.ssh-hosts-*')))
 def test_host_key_fetch_never_authenticates(self):
  calls=[]
  class Transport:
   def __init__(self,sock):pass
   def start_client(self,timeout):calls.append('handshake')
   def get_remote_server_key(self):return types.SimpleNamespace(asbytes=lambda:b'public-key')
   def close(self):pass
   def auth_password(self,*args):raise AssertionError('no authentication allowed')
  sock=types.SimpleNamespace(close=lambda:None)
  with patch.object(backend,'get_paramiko',return_value=types.SimpleNamespace(Transport=Transport)),patch.object(socket,'create_connection',return_value=sock):result=backend.fingerprints(self.settings)
  self.assertEqual(set(result),{'ru','nl'});self.assertEqual(calls,['handshake','handshake'])
 def test_key_fetch_error_names_server_and_redacts_error(self):
  with patch.object(backend,'get_paramiko',return_value=object()),patch.object(socket,'create_connection',side_effect=OSError('PRIVATE-RU')),self.assertRaises(backend.UserError) as error:backend.fingerprints(self.settings)
  self.assertIn('российский сервер 8.8.8.8:22',str(error.exception));self.assertNotIn('PRIVATE-RU',str(error.exception))

class SSHTrustAPI(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.path=pathlib.Path(self.temp.name)/'ssh-hosts.json';self.application=app.Application(self.path);self.server=app.Server(('127.0.0.1',0),self.application)
  self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
 def tearDown(self):self.server.shutdown();self.server.server_close();self.temp.cleanup()
 def request(self,path,payload,token=None):
  conn=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=10)
  conn.request('POST',path,json.dumps(payload),{'X-Local-Token':token or self.application.token,'Content-Type':'application/json'})
  response=conn.getresponse();body=json.loads(response.read());conn.close();return response.status,body
 def test_prepare_confirm_and_known_reconnect(self):
  with patch.object(backend,'fingerprints',return_value=pins()):
   code,p=self.request('/api/ssh/prepare',data());self.assertEqual(code,200);self.assertTrue(p['confirmation_required'])
   self.assertEqual(self.request('/api/ssh/confirm',{'confirmation_token':p['confirmation_token']})[0],400);self.assertFalse(self.path.exists())
   self.assertEqual(self.request('/api/ssh/confirm',{'confirmation_token':p['confirmation_token'],'accept':True})[0],200)
   code,p=self.request('/api/ssh/prepare',data());self.assertEqual(code,200);self.assertFalse(p['confirmation_required'])
 def test_unauthorized_prepare_has_no_network_and_direct_job_is_blocked(self):
  with patch.object(backend,'fingerprints',side_effect=AssertionError('no network')):
   self.assertEqual(self.request('/api/ssh/prepare',data(),token='wrong')[0],403)
  self.assertEqual(self.request('/api/jobs',data())[0],400);self.assertFalse(self.application.jobs)
 def test_changed_key_api_never_starts_job(self):
  p=self.application.trust.prepare(backend.validate(data()),pins());self.application.trust.confirm(p['confirmation_token']);before=self.path.read_bytes()
  with patch.object(backend,'fingerprints',return_value=dict(pins(),ru='SHA256:'+'C'*43)):
   code,body=self.request('/api/ssh/prepare',data());self.assertEqual(code,400);self.assertIn('ключ изменился',body['error'])
  self.assertFalse(self.application.jobs);self.assertEqual(self.path.read_bytes(),before)
