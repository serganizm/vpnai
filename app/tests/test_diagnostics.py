import contextlib,io,json,pathlib,sys,tempfile,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import backend,diagnostics
from test_app import settings

class DiagnosticsTests(unittest.TestCase):
 def test_live_vpn_without_state_and_with_existing_routes(self):
  endpoints=[]
  class Remote:
   def __init__(self,role,settings):self.role=role;endpoints.append(self)
   def connect(self):pass
   def close(self):pass
   def lock(self):raise AssertionError('Diagnostic must not create a server lock file')
   def inventory(self):return {'managed':False,'os':{'ID':'ubuntu'},'routes':[{'dst':'10.77.0.0/24'}]}
   def shell(self,code,quiet=False):
    assert code==backend.SYSTEM_INFO
    return 'ubuntu\n26.04\n3.14.4\n'
   def python(self,code,data=None):
    if code==diagnostics.RUNTIME:return json.dumps([{'check':'Working VPN','passed':True,'detail':'active'}])
    if code==backend.INSPECT_MODES:return json.dumps({'profiles':[{'split':True,'redirect':False,'password':True}]*2,'list_classifier':True,'split_tools':True})
    if 'state.json' in code:return 'null'
    raise AssertionError('Unexpected command')
  for action in ['check','verify']:
   with self.subTest(action=action),patch.object(backend,'Remote',Remote),patch.object(backend.engine,'preflight',side_effect=AssertionError('Fresh preflight called')),patch.object(backend.engine,'verify',side_effect=AssertionError('Mutating probe called')):
    job=backend.Job(settings(demo=False,action=action));job.run()
    self.assertEqual(job.status,'success',job.events);self.assertEqual(job.report['routing'],'split');self.assertGreaterEqual(len(job.report['warnings']),2)
    self.assertTrue(job.report['checks']);self.assertTrue(job.report['full_check'])
 def test_runtime_detects_ports_without_exposing_keys_or_changing_services(self):
  with tempfile.TemporaryDirectory() as tmp:
   server=pathlib.Path(tmp)/'server';server.mkdir();(server/'legacy.conf').write_text('server 10.77.0.0 255.255.255.0\nproto udp\nport 1194\n<key>\nPRIVATE-SECRET\n</key>\n')
   script=diagnostics.RUNTIME.replace('/etc/openvpn/server',str(server)).replace("pathlib.Path('/etc/openvpn')",'pathlib.Path('+repr(str(pathlib.Path(tmp)/'empty'))+')')
   commands=[]
   def run(args,**kwargs):
    commands.append(args)
    from types import SimpleNamespace
    if args[0]=='systemctl':return SimpleNamespace(returncode=0,stdout='active\n')
    if args[0]=='ss':return SimpleNamespace(returncode=0,stdout='UNCONN 0 0 0.0.0.0:1194 0.0.0.0:*\n')
    if args[0]=='ip':return SimpleNamespace(returncode=0,stdout='[]')
    return SimpleNamespace(returncode=1,stdout='')
   output=io.StringIO()
   with patch('subprocess.run',run),contextlib.redirect_stdout(output):exec(script,{'DATA':{'role':'ru','peer':'9.9.9.9'}})
   rows=json.loads(output.getvalue());self.assertTrue(next(x['passed'] for x in rows if x['check']=='Порт legacy'))
   self.assertNotIn('PRIVATE-SECRET',output.getvalue());self.assertTrue(all(c[:2]!=['systemctl','restart'] for c in commands))
 def test_unknown_runtime_is_not_reported_as_healthy(self):
  class EP:
   role='ru'
   def python(self,*args):return '[]'
  result=diagnostics.inspect_servers({'nl_ip':'9.9.9.9'},[EP()],{'ru':{'managed':False,'os':{}}},verify=True)
  self.assertFalse(result['healthy']);self.assertFalse(result['complete'])
