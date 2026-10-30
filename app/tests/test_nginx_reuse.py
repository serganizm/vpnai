import contextlib,io,json,pathlib,subprocess,sys,tempfile,types,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import backend
engine=backend.engine
class NginxProbe(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name)
  self.pair={'ru_ip':'8.8.8.8','nl_ip':'9.9.9.9'};self.receipt=dict(role='ru',complete=True,pair=self.pair)
  self.config='http { server { listen 80 default_server; server_name _; } }\n# server_name example.com;';self.owner='nginx';self.valid=True;self.custom=False
 def P(self,name):
  if name=='/etc/nginx/sites-enabled':return types.SimpleNamespace(iterdir=lambda:[types.SimpleNamespace(name='default',resolve=lambda:self.P('/etc/nginx/sites-available/default'))])
  if name=='/etc/nginx/conf.d':return types.SimpleNamespace(glob=lambda pattern:['custom.conf'] if self.custom else [])
  return self.root/str(name).lstrip('/')
 def probe(self):
  f=self.P('/var/lib/ovpn-installer-removal.json');f.parent.mkdir(parents=True,exist_ok=True);f.write_text(json.dumps(self.receipt))
  def run(args,**kwargs):return types.SimpleNamespace(returncode=0 if args[0]=='ss' or self.valid else 1,stdout='LISTEN users:(("'+self.owner+'",pid=1,fd=6))' if args[0]=='ss' else self.config)
  out=io.StringIO()
  with patch('subprocess.run',side_effect=run),contextlib.redirect_stdout(out):exec(engine.NGINX_REUSE_PROBE.replace('p=pathlib.Path','p=TEST_PATH'),{'DATA':self.pair,'TEST_PATH':self.P})
  return json.loads(out.getvalue())
 def test_default_nginx_after_own_removal(self):self.assertTrue(self.probe())
 def test_other_listener_rejected(self):self.owner='apache2';self.assertFalse(self.probe())
 def test_custom_include_rejected(self):self.custom=True;self.assertFalse(self.probe())
 def test_custom_server_name_rejected(self):self.config='server_name example.org;';self.assertFalse(self.probe())
 def test_invalid_config_rejected(self):self.valid=False;self.assertFalse(self.probe())
 def test_other_pair_rejected(self):self.receipt['pair']={};self.assertFalse(self.probe())
 def test_no_complete_receipt_rejected(self):self.receipt['complete']=False;self.assertFalse(self.probe())
 def test_wrong_role_rejected(self):self.receipt['role']='nl';self.assertFalse(self.probe())
class NginxPreflight(unittest.TestCase):
 def check(self,port,reuse):
  self.writes=[];self.probes=[]
  class EP:
   role='ru'
   def python(ep,code,data):
    if code==engine.NGINX_REUSE_PROBE:self.probes.append(data);return json.dumps(reuse)
    return '0'
   def write(ep,*a,**kw):self.writes.append(a)
  c=dict(ru_ip='8.8.8.8',nl_ip='9.9.9.9',vpn_net='10.77.0.0/24',tcp_net='10.79.0.0/24',gre_net='10.78.0.0/30',ovpn_port=1194)
  inv=dict(os={'ID':'ubuntu','VERSION_ID':'26.04'},addr=[{'addr_info':[{'family':'inet','local':'8.8.8.8'}]}],routes=[{'dst':'default','dev':'eth0'}],routes6=[],sysctl={},reserved_files=[],links=[],table='',rules='',swan='inactive',xfrm='',managed=False,sockets='tcp LISTEN 0 511 0.0.0.0:'+str(port)+' 0.0.0.0:*')
  engine.preflight(c,EP(),inv,False)
 def test_reuses_proven_default_nginx(self):self.check(80,True);self.assertEqual(len(self.probes),1);self.assertEqual(len(self.writes),1)
 def test_unknown_port80_rejected(self):
  with self.assertRaisesRegex(engine.InstallError,'порт 80'):self.check(80,False)
  self.assertFalse(self.writes)
 def test_port443_still_rejected(self):
  with self.assertRaisesRegex(engine.InstallError,'порт 443'):self.check(443,True)
  self.assertFalse(self.probes)
 def test_openvpn_port_still_rejected(self):
  with self.assertRaisesRegex(engine.InstallError,'порт 1194'):self.check(1194,True)
 def test_unrelated_port_ignored(self):self.check(8080,False);self.assertFalse(self.probes)
