import pathlib,sys,unittest,types
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import app
class IndependentConnections(unittest.TestCase):
 def setUp(self):self.application=app.Application();self.data={'ru':{'host':'8.8.8.8','password':'ru'},'nl':{'host':'9.9.9.9','password':'nl'}}
 def tearDown(self):self.application.close()
 def test_admin_alone_does_not_light_installation(self):
  self.application.admin.connected=True
  self.assertFalse(self.application.installation_connected())
 def test_installation_alone_does_not_light_admin(self):
  self.application.session=self.data;self.application.install_signature=self.application.connection_signature(self.data)
  self.assertTrue(self.application.installation_connected());self.assertFalse(self.application.admin.connected)
 def test_both_connected_and_admin_disconnect_is_independent(self):
  self.application.session=self.data;self.application.install_signature=self.application.connection_signature(self.data);self.application.admin.connected=True
  self.assertTrue(self.application.installation_connected());self.assertTrue(self.application.admin.connected)
  self.application.admin.close();self.assertTrue(self.application.installation_connected())
 def test_changed_credentials_reset_only_installation(self):
  self.application.session=self.data;self.application.install_signature=self.application.connection_signature(self.data);self.application.admin.connected=True
  self.data['ru']['password']='changed'
  self.assertFalse(self.application.installation_connected());self.assertTrue(self.application.admin.connected)
 def test_failed_operation_not_connected(self):
  self.application.session=self.data
  self.application.jobs={'job':types.SimpleNamespace(ssh_connected=True,connection_signature=self.application.connection_signature(self.data),status='error')}
  self.assertFalse(self.application.installation_connected());self.application.jobs={}
 def test_port_string_and_integer_are_equivalent(self):
  self.application.session=self.data;self.application.session['ru']['port']='22'
  other={'ru':dict(self.data['ru'],port=22),'nl':self.data['nl']}
  self.application.install_signature=self.application.connection_signature(other)
  self.assertTrue(self.application.installation_connected())

 def test_later_install_check_not_overwritten_by_old_completed_job(self):
  old_signature=self.application.connection_signature(self.data);self.application.session=self.data
  self.application.jobs={'job':types.SimpleNamespace(ssh_connected=True,connection_signature=old_signature,status='success')}
  self.assertTrue(self.application.installation_connected())
  self.application.session={'ru':{'host':'8.8.4.4','password':'other'},'nl':self.data['nl']}
  self.application.install_signature=self.application.connection_signature(self.application.session)
  self.assertTrue(self.application.installation_connected());self.application.jobs={}
