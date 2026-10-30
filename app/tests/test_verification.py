"""Regression cases from the legacy-server investigation; no real SSH or VPS changes."""
import ast,contextlib,io,json,pathlib,subprocess,sys,types,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import backend
from test_app import settings
engine=backend.engine

class VerificationRegression(unittest.TestCase):
 class EP:
  def __init__(self,role,status=None,failed=False):self.role=role;self.status=status;self.calls=[];self.writes=[];self.failed=failed
  def shell(self,code,quiet=False):
   self.calls.append(code)
   if self.failed:raise backend.UserError('неактивна обязательная служба ovpn-links')
   return 'INSTALLED'
  def python(self,code,data=None):
   self.calls.append(code)
   if 'split-status.json' in code:return json.dumps(self.status)
   return '{}'
  def write(self,*args):self.writes.append(args)
 def config(self,mode):return dict(backend.config(settings(ru={'host':'8.8.8.8'},nl={'host':'9.9.9.9'})),routing_mode=mode)
 def test_full_modes_do_not_require_split_status(self):
  for mode in ('full_mixed','full_nl'):
   ru,nl=self.EP('ru'),self.EP('nl');result=engine.verify(self.config(mode),ru,nl,write_report=False)
   self.assertEqual(result['split_routes']['status'],'not_applicable')
   self.assertFalse(any('split-status.json' in c for c in ru.calls));self.assertFalse(ru.writes)
 def test_split_requires_real_status_not_fabricated_success(self):
  for status in (None,{}, {'default_route':True,'ipv4_routes':10}):
   ru,nl=self.EP('ru',status),self.EP('nl')
   with self.subTest(status=status),self.assertRaisesRegex(engine.InstallError,'split-status.json'):engine.verify(self.config('split'),ru,nl,write_report=False)
   self.assertFalse(ru.writes)
 def test_split_valid_status_and_persistent_install_report(self):
  status={'default_route':False,'ipv4_routes':123};ru,nl=self.EP('ru',status),self.EP('nl')
  result=engine.verify(self.config('split'),ru,nl)
  self.assertEqual(result['split_routes'],status);self.assertEqual(len(ru.writes),1)
 def test_service_failure_names_stage_and_server(self):
  with self.assertRaisesRegex(engine.InstallError,'Службы.*зарубежный.*ovpn-links'):engine.verify(self.config('full_mixed'),self.EP('ru'),self.EP('nl',failed=True))
 def test_safe_diagnostics_never_echo_unknown_remote_output(self):
  self.assertEqual(engine.diagnostic_message('secret-password\nVPNAI_DIAG:unknown-secret'), '')
  self.assertIn('NL',engine.diagnostic_message('VPNAI_DIAG:NL_EXIT'))
  self.assertIn('ovpn-links',engine.diagnostic_message('VPNAI_DIAG:SERVICE:ovpn-links'))
 def test_inspection_reads_directives_but_never_outputs_key_material(self):
  with __import__('tempfile').TemporaryDirectory() as tmp:
   base=pathlib.Path(tmp);conf=base/'server';conf.mkdir()
   for name in ('ru.conf','ru-tcp.conf'):(conf/name).write_text('# client-connect /usr/local/libexec/ovpn-split-connect\npush "redirect-gateway def1 ipv6"\nauth-user-pass-verify /auth.py via-file\n<key>\nDO-NOT-EXPOSE-KEY\n</key>\n')
   network=base/'network';network.write_text('--match-set ovpn_nl dst')
   code=backend.INSPECT_MODES.replace('/etc/openvpn/server',conf.as_posix()).replace('/usr/local/sbin/ovpn-network',network.as_posix());out=io.StringIO()
   with contextlib.redirect_stdout(out):exec(code,{})
   result=json.loads(out.getvalue());self.assertTrue(all(p['redirect'] and not p['split'] and p['password'] for p in result['profiles']));self.assertNotIn('DO-NOT-EXPOSE',out.getvalue())
 def test_detects_legacy_and_rejects_inconsistent_udp_tcp_modes(self):
  ep=self.EP('ru');old={'version':1,'config':{}}
  for profiles,expected in [([{'redirect':True,'split':False,'password':True}]*2,'full_mixed'),([{'redirect':False,'split':True,'password':True}]*2,'split'),([{'redirect':False,'split':True,'password':True},{'redirect':True,'split':False,'password':True}],'unknown')]:
   ep.python=lambda code:json.dumps({'profiles':profiles,'list_classifier':True,'split_tools':False})
   result=backend.installed_modes(ep,old);self.assertEqual(result['routing'],expected);self.assertTrue(result['legacy'])
 def test_probe_error_is_labelled_and_temporary_resources_cleaned(self):
  calls=[]
  def run(args,**kwargs):
   calls.append(args)
   return types.SimpleNamespace(returncode=28 if 'curl' in args else 0,stdout='',stderr='PRIVATE-REMOTE-OUTPUT')
  out=io.StringIO();c=self.config('full_mixed')
  with patch.object(subprocess,'run',side_effect=run),contextlib.redirect_stdout(out),self.assertRaises(SystemExit):exec(engine.PROBE,{'DATA':c,'json':json})
  self.assertIn('VPNAI_DIAG:NL_EXIT',out.getvalue());self.assertNotIn('PRIVATE-REMOTE',out.getvalue())
  self.assertIn(('ip','netns','del','ovpn-install-check'),[tuple(c) for c in calls])
 def test_ssh_authentication_failure_names_server_without_secret(self):
  class AuthenticationException(Exception):pass
  class Client:
   def set_missing_host_key_policy(self,policy):pass
   def connect(self,**kw):raise AuthenticationException('DO-NOT-EXPOSE-PASSWORD')
   def close(self):pass
  pm=types.SimpleNamespace(SSHClient=Client,MissingHostKeyPolicy=object,AuthenticationException=AuthenticationException)
  ep=backend.Remote('nl',{'host':'9.9.9.9','port':2222,'fingerprint':'pin','method':'password','password':'DO-NOT-EXPOSE-PASSWORD'})
  with patch.object(backend,'get_paramiko',return_value=pm),self.assertRaises(backend.UserError) as caught:ep.connect()
  self.assertIn('зарубежный сервер 9.9.9.9:2222',str(caught.exception));self.assertNotIn('DO-NOT-EXPOSE',str(caught.exception))
 def test_legacy_verify_uses_actual_mode_and_does_not_write_servers(self):
  endpoints=[];previous={'version':1,'config':self.config('full_mixed')};previous['config'].pop('routing_mode');previous['config'].pop('auth_mode')
  class Fake(self.EP):
   def __init__(self,role,settings):super().__init__(role);self.settings=settings;self.closed=False;endpoints.append(self)
   def connect(self):pass
   def lock(self):pass
   def close(self):self.closed=True;self.settings.clear()
   def inventory(self):return {'managed':True,'os':{},'swan':'active','reserved_files':[]}
   def shell(self,code,quiet=False):return 'ubuntu\n24.04\n3.12.3\n' if code==backend.SYSTEM_INFO else ''
   def python(self,code,data=None):
    if code==backend.INSPECT_MODES:return json.dumps({'profiles':[{'redirect':True,'split':False,'password':True}]*2,'list_classifier':True,'split_tools':False})
    if 'state.json' in code:return json.dumps(previous)
    return '{}'
  for action in ('verify','resume'):
   endpoints.clear()
   job=backend.Job(settings(demo=False,action=action,ru={'host':'8.8.8.8','password':'private-ru'},nl={'host':'9.9.9.9','password':'private-nl'}))
   with patch.object(backend,'Remote',Fake),patch.object(engine,'verify',return_value={'passed':True}) as verify,patch.object(backend,'collect',return_value=b'archive'):job.run()
   self.assertEqual(job.report['routing'],'full_mixed');self.assertEqual(job.report['requested_routing'],'split');self.assertTrue(job.report['warnings'])
   if action=='verify':
    self.assertEqual(job.status,'success',job.events);self.assertFalse(verify.call_args.kwargs['write_report'])
   else:
    self.assertEqual(job.status,'error');verify.assert_not_called();self.assertIn('Восстановление сохраняет',job.events[-1]['message'])
   self.assertFalse(any(ep.writes for ep in endpoints));self.assertTrue(all(ep.closed for ep in endpoints));self.assertNotIn('private-ru',json.dumps(job.public()))
 def test_generated_verification_shell_syntax(self):
  if sys.platform=='win32':self.skipTest('Shell syntax is checked on Unix and in Linux CI')
  class SyntaxEP(self.EP):
   def shell(self,code,quiet=False):
    subprocess.run(['bash','-n'],input=code,text=True,check=True,capture_output=True)
    return ''
  engine.verify(self.config('full_mixed'),SyntaxEP('ru'),SyntaxEP('nl'),write_report=False)
 def test_corrupt_split_status_names_the_failed_stage(self):
  ru=self.EP('ru');original=ru.python
  ru.python=lambda code,data=None:'{' if 'split-status' in code else original(code,data)
  with self.assertRaisesRegex(engine.InstallError,'Состояние раздельных маршрутов.*JSONDecodeError'):engine.verify(self.config('split'),ru,self.EP('nl'),write_report=False)

 def test_missing_bundled_ssh_never_requests_pip_or_setup_script(self):
  import builtins
  original=builtins.__import__
  def importing(name,*args,**kwargs):
   if name=='paramiko':raise ImportError('missing bundled module')
   return original(name,*args,**kwargs)
  with patch.object(sys,'frozen',True,create=True),patch.object(builtins,'__import__',side_effect=importing),self.assertRaises(backend.UserError) as error:backend.get_paramiko()
  self.assertIn('Встроенный',str(error.exception));self.assertNotIn('setup-ssh',str(error.exception))
