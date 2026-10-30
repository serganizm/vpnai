"""Graceful desktop shutdown without killing an active VPN installation."""
import http.client,json,pathlib,sys,tempfile,threading,types,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import app
class ExitAPI(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.application=app.Application(pathlib.Path(self.temp.name)/'trust.json');self.server=app.Server(('127.0.0.1',0),self.application);self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
 def tearDown(self):self.server.shutdown();self.server.server_close();self.temp.cleanup()
 def post(self,token):
  c=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=5);c.request('POST','/api/exit','{}',{'X-Local-Token':token,'Content-Type':'application/json'});r=c.getresponse();r.read();c.close();return r.status
 def test_idle_app_exits_cleanly(self):
  self.assertEqual(self.post(self.application.token),200);self.thread.join(5);self.assertFalse(self.thread.is_alive());self.assertTrue(self.application.stopping)
 def test_active_job_prevents_exit(self):
  self.application.jobs['active']=types.SimpleNamespace(status='running')
  self.assertEqual(self.post(self.application.token),400);self.assertFalse(self.application.stopping);self.assertTrue(self.thread.is_alive())
 def test_unauthorized_exit_is_rejected(self):
  self.assertEqual(self.post('wrong'),403);self.assertFalse(self.application.stopping)
