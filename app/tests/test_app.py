import ast,contextlib,hashlib,http.client,importlib.util,io,json,pathlib,socket,sys,tempfile,threading,time,unittest,zipfile
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import backend,app

def settings(**kw):
 d={'demo':True,'initial_user':'tester','ru_routes':'','eu_routes':''};d.update(kw);return backend.validate(d)
class Validation(unittest.TestCase):
 def test_defaults_empty_and_demo(self):
  d=settings();self.assertTrue(d['demo']);self.assertEqual(d['ru_routes'],[]);self.assertEqual(d['eu_routes'],[])
 def test_real_requires_public_hosts_and_credentials(self):
  for change in [{'demo':False},{'ru_routes':'192.168.1.1'},{'eu_routes':'0.0.0.0/0'},{'routing':'bad'},{'auth':'bad'},{'vpn_port':8765},{'initial_user':'x;command'},{'comment':'bad\x1b'}]:
   with self.subTest(change=change),self.assertRaises(backend.UserError):settings(**change)
 def test_normalizes_and_deduplicates(self):
  self.assertEqual(backend.cidrs('9.9.9.9\n9.9.9.9/32\n8.8.8.9/24 # example'),['8.8.8.0/24','9.9.9.9/32'])
 def test_destructive_confirmation(self):
  with self.assertRaises(backend.UserError):settings(action='remove')
  self.assertEqual(settings(action='remove',confirmation='УДАЛИТЬ')['action'],'remove')
class Templates(unittest.TestCase):
 def test_modes_compile_and_auth(self):
  for mode in backend.MODES:
   for auth in backend.AUTH:
    c=backend.config(settings(routing=mode,auth=auth,ru={'host':'8.8.8.8'},nl={'host':'9.9.9.9'}));backend.engine.validate(c)
    for p in (ROOT/'core/payload').rglob('*'):
     if not p.is_file():continue
     role=p.relative_to(ROOT/'core/payload').parts[0];s=backend.render(p.read_text(),c,role)
     self.assertNotIn('@@',s,str(p))
     if s.startswith('#!/usr/bin/python3'):ast.parse(s)
    for name in ['ru.conf','ru-tcp.conf']:
     s=backend.render((ROOT/'core/payload/ru/etc/openvpn/server'/name).read_text(),c,'ru')
     self.assertEqual('redirect-gateway def1' in s,mode!='split')
     self.assertEqual('auth-user-pass-verify' in s,auth=='password')
     self.assertIn('verify-client-cert require',s)
    source=backend.render((ROOT/'core/payload/ru/usr/local/sbin/ovpn-user').read_text(),c,'ru')
    tree=ast.parse(source);profiles=[n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,str) and n.value.startswith('client\n')]
    self.assertEqual('auth-user-pass' in profiles[0],auth=='password')
    if auth=='certificate':self.assertNotIn('Password: ',source)
 def test_all_nl_classifier(self):
  c=backend.config(settings(routing='full_nl'));s=backend.render((ROOT/'core/payload/ru/usr/local/sbin/ovpn-network').read_text(),c,'ru')
  self.assertNotIn('--match-set ovpn_nl dst',s);self.assertNotIn('--match-set ovpn_force_ru dst',s)
 def test_empty_seed_and_no_metadata(self):
  self.assertEqual((ROOT/'core/own-ru.txt').read_text(),'')
  for p in ROOT.rglob('*'):
   self.assertFalse(p.name.startswith('._') or p.name in ('.DS_Store','__MACOSX'))
 def test_cleanup_syntax(self):ast.parse(backend.CLEAN)
class Demo(unittest.TestCase):
 def test_success_no_network_or_real_profiles(self):
  job=backend.Job(settings(action='install'))
  with patch.object(socket,'create_connection',side_effect=AssertionError('network forbidden')),patch.object(threading.Event,'wait',return_value=False):job.run()
  self.assertEqual(job.status,'success');self.assertTrue(job.report['demo']);self.assertEqual(job.settings,{})
  with zipfile.ZipFile(io.BytesIO(job.artifact)) as z:self.assertEqual(set(z.namelist()),{'DEMO-README.txt','plan.json'})
 def test_error_and_cancel(self):
  job=backend.Job(settings(scenario='failure'))
  with patch.object(threading.Event,'wait',return_value=False):job.run()
  self.assertEqual(job.status,'error');self.assertIsNone(job.artifact)
  job=backend.Job(settings());job.cancel.set();job.run();self.assertEqual(job.status,'cancelled')
 def test_check_no_archive(self):
  job=backend.Job(settings(action='check'))
  with patch.object(threading.Event,'wait',return_value=False):job.run()
  self.assertEqual(job.status,'success');self.assertIsNone(job.artifact)
class Controller(unittest.TestCase):
 def test_real_install_pipeline_with_fake_servers_and_empty_lists(self):
  for updates in (False,True):
   with self.subTest(update_packages=updates):self.install_pipeline(updates)
 def install_pipeline(self,updates):
  endpoints=[]
  class Fake:
   def __init__(self,role,settings):self.role=role;self.settings=settings;self.files={};self.commands=[];self.closed=False;endpoints.append(self)
   def connect(self):pass
   def lock(self):pass
   def close(self):self.closed=True;self.settings.clear()
   def inventory(self):return {'os':{'ID':'ubuntu','VERSION_ID':'24.04'},'addr':[{'addr_info':[{'family':'inet','local':'8.8.8.8' if self.role=='ru' else '9.9.9.9'}]}],'routes':[{'dst':'default','dev':'eth0'}],'routes6':[],'links':[],'rules':'','table':'','swan':'inactive','xfrm':'','sockets':'','managed':False,'reserved_files':[],'sysctl':{}}
   def write(self,path,text,mode=0o600,preserve=False):
    if not preserve or path not in self.files:self.files[path]=text
   def shell(self,script,quiet=False):
    self.commands.append(script)
    if script==backend.SYSTEM_INFO:return 'ubuntu\n24.04\n3.12.3\n'
    return '  gre: #1, reqid 1, INSTALLED, TRANSPORT' if 'swanctl --list-sas' in script else ''
   def python(self,code,data=None):
    if 'state.json' in code:return 'null'
    if 'sysctl' in code:return '0'
    return ''
  s=settings(demo=False,action='install',update_packages=updates,ru={'host':'8.8.8.8','password':'secret-ru','fingerprint':'pin'},nl={'host':'9.9.9.9','password':'secret-nl','fingerprint':'pin'})
  job=backend.Job(s)
  with patch.object(backend,'Remote',Fake),patch.object(backend.engine,'verify',return_value={'passed':True}),patch.object(backend,'collect',return_value=b'archive'):
   job.run()
  self.assertEqual(job.status,'success',job.events)
  ru=endpoints[0];self.assertEqual(ru.files['/etc/ovpn-routing/force-ru.txt'],'\n');self.assertEqual(ru.files['/etc/ovpn-routing/extra-nl.txt'],'\n')
  self.assertTrue(json.loads(ru.files['/var/lib/ovpn-installer/state.json'])['complete'])
  self.assertNotIn('secret-ru',json.dumps(job.public()))
  self.assertTrue(all(ep.closed for ep in endpoints))
  self.assertEqual(job.report['update_packages'],updates)
  for ep in endpoints:self.assertEqual(any('upgrade -y' in command for command in ep.commands),updates)
 def test_changed_ssh_host_key_rejected(self):
  import types
  key=types.SimpleNamespace(asbytes=lambda:b'server-key')
  class Client:
   def set_missing_host_key_policy(self,policy):self.policy=policy
   def connect(self,**kw):self.policy.missing_host_key(self,kw['hostname'],key)
   def close(self):pass
   def get_transport(self):return types.SimpleNamespace(set_keepalive=lambda n:None)
  pm=types.SimpleNamespace(SSHClient=Client,MissingHostKeyPolicy=object)
  remote=backend.Remote('ru',{'host':'8.8.8.8','port':22,'fingerprint':'wrong','method':'password','password':'secret'})
  with patch.object(backend,'get_paramiko',return_value=pm),patch.object(remote,'shell') as shell:
   with self.assertRaises(backend.UserError):remote.connect()
   shell.assert_not_called()
  remote.close()
class HTTP(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.application=app.Application();cls.server=app.Server(('127.0.0.1',0),cls.application);cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
 @classmethod
 def tearDownClass(cls):cls.server.shutdown();cls.server.server_close()
 def request(self,path,method='GET',data=None,headers=None):
  c=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=10)
  h={'X-Local-Token':self.application.token};h.update(headers or {})
  if data is not None:h['Content-Type']='application/json';data=json.dumps(data)
  c.request(method,path,data,h);r=c.getresponse();result=(r.status,r.read(),dict(r.headers));c.close();return result
 def test_static_csp_and_traversal(self):
  code,body,headers=self.request('/');self.assertEqual(code,200);self.assertIn('Content-Security-Policy',headers)
  self.assertEqual(self.request('/../backend.py')[0],404)
 def test_ssh_command_api_no_execution(self):
  original=socket.create_connection
  def local_only(address,*args,**kwargs):
   if address[0]!='127.0.0.1':raise AssertionError('external connection forbidden')
   return original(address,*args,**kwargs)
  with patch.object(backend.socket,'create_connection',side_effect=local_only):
   code,body,_=self.request('/api/ssh-command','POST',{'host':'8.8.8.8','port':2222,'platform':'windows'})
  self.assertEqual(code,200);self.assertIn('ssh -p 2222 root@8.8.8.8',json.loads(body)['command'])
  self.assertIn(json.loads(self.request('/api/info')[1])['platform'],('macos','linux','windows'))
 def test_auth_and_origin(self):
  self.assertEqual(self.request('/api/info',headers={'X-Local-Token':'bad'})[0],403)
  self.assertEqual(self.request('/api/jobs','POST',{},headers={'Origin':'https://example.org'})[0],403)
  self.assertEqual(self.request('/api/info',headers={'Host':'example.org'})[0],403)
 def test_job_report_download_and_secret_absence(self):
  data={'demo':True,'action':'install','ru':{'password':'must-not-leak'},'nl':{'password':'also-private'}}
  with patch.object(threading.Event,'wait',return_value=False):
   code,body,_=self.request('/api/jobs','POST',data);self.assertEqual(code,202);job_id=json.loads(body)['id']
   for _ in range(100):
    job=self.application.jobs[job_id]
    if job.status!='running':break
    time.sleep(.01)
  code,body,_=self.request('/api/jobs/'+job_id);self.assertEqual(code,200);self.assertNotIn(b'must-not-leak',body);self.assertNotIn(b'also-private',body)
  self.assertEqual(self.request('/api/jobs/'+job_id+'/download')[0],200)
  job.expires=0;self.assertEqual(self.request('/api/jobs/'+job_id+'/download')[0],410)

class SSHCommands(unittest.TestCase):
 def test_unix_ip_and_port(self):
  for system in ('macos','linux'):
   result=backend.ssh_copy_command('8.8.8.8',2222,system)
   self.assertEqual(result['command'],'ssh-copy-id -i ~/.ssh/id_ed25519.pub -p 2222 root@8.8.8.8')
   self.assertIn('cat ~/.ssh/id_ed25519.pub | ssh -p 2222 root@8.8.8.8',result['fallback'])
 def test_windows_powershell(self):
  s=backend.ssh_copy_command('9.9.9.9',2200,'windows')['command']
  self.assertIn('Get-Content',s);self.assertIn('id_ed25519.pub',s);self.assertIn('ssh -p 2200 root@9.9.9.9',s)
  self.assertIn('cat >> ~/.ssh/authorized_keys',s);self.assertNotIn('ssh-copy-id',s)
 def test_custom_key_and_reject_injection(self):
  s=backend.ssh_copy_command('8.8.8.8',22,'linux','~/my key')['command']
  self.assertIn("'my key.pub'",s)
  for host,port,system in [('8.8.8.8;cmd',22,'linux'),('8.8.8.8',0,'macos'),('8.8.8.8',22,'unknown')]:
   with self.assertRaises(backend.UserError):backend.ssh_copy_command(host,port,system)
 def test_local_key_method_keeps_key_out_of_browser(self):
  d=settings(demo=False,ru={'host':'8.8.8.8','method':'local-key','key_path':'~/.ssh/id_ed25519'},nl={'host':'9.9.9.9','password':'secret'})
  self.assertEqual(d['ru']['method'],'local-key');self.assertEqual(d['ru']['key'],'')



class SystemPreparation(unittest.TestCase):
 class EP:
  role='ru'
  def __init__(self,python='missing',os='ubuntu',version='24.04'):self.version=python;self.os=os;self.os_version=version;self.calls=[]
  def shell(self,script,quiet=False):
   self.calls.append(script)
   if script==backend.SYSTEM_INFO:return self.os+'\n'+self.os_version+'\n'+self.version+'\n'
   if 'install -y python3' in script:self.version='3.12.3'
   if 'reboot-required' in script:return 'yes'
   return ''
 def test_python_installed_when_missing(self):
  ep=self.EP();info=backend.system_info(ep);backend.ensure_python(ep,info,True)
  self.assertTrue(info['python_installed']);self.assertEqual(info['python'],'3.12.3')
  self.assertTrue(any('install -y python3' in c for c in ep.calls))
 def test_present_python_not_reinstalled(self):
  ep=self.EP('3.12.3');info=backend.system_info(ep);ep.calls.clear();backend.ensure_python(ep,info,True)
  self.assertEqual(ep.calls,[])
 def test_read_only_missing_python_does_not_install(self):
  ep=self.EP();info=backend.system_info(ep);ep.calls.clear()
  with self.assertRaises(backend.UserError):backend.ensure_python(ep,info,False)
  self.assertEqual(ep.calls,[])
 def test_unsupported_os_stops_before_install(self):
  ep=self.EP(os='alpine',version='3.20')
  with self.assertRaises(backend.UserError):backend.system_info(ep)
  self.assertEqual(ep.calls,[backend.SYSTEM_INFO])
 def test_updates_keep_configuration_and_report_reboot(self):
  ep=self.EP('3.12.3');info=backend.system_info(ep);backend.update_system(ep,info)
  cmd=next(c for c in ep.calls if 'upgrade -y' in c)
  self.assertIn('--force-confold',cmd);self.assertIn('Lock::Timeout=300',cmd)
  self.assertTrue(info['packages_updated']);self.assertTrue(info['reboot_required'])
  self.assertFalse(any(c.strip().startswith(('reboot','shutdown')) for c in ep.calls))



class OptionalUpdates(unittest.TestCase):
 def test_option_defaults_and_type(self):
  self.assertFalse(settings()['update_packages'])
  self.assertTrue(settings(update_packages=True)['update_packages'])
  for invalid in ('false','yes',1,None):
   with self.assertRaises(backend.UserError):settings(update_packages=invalid)
 def test_demo_reports_selection(self):
  for updates in (False,True):
   job=backend.Job(settings(action='install',update_packages=updates))
   with patch.object(threading.Event,'wait',return_value=False):job.run()
   self.assertEqual(job.status,'success');self.assertEqual(job.report['update_packages'],updates)
   self.assertTrue(any(('ОС включено' if updates else 'ОС пропущено') in e['message'] for e in job.events))

if __name__=='__main__':unittest.main()
