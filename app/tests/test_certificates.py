"""Certificate and relay regression tests run without VPS or ACME issuance."""
import contextlib,io,json,os,pathlib,socket,subprocess,sys,tempfile,threading,types,unittest
from unittest.mock import patch,Mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import backend
engine=backend.engine

def load(relative):
 path=engine.ROOT/'payload'/relative
 code=engine.render(path.read_text(),dict(ru_ip='8.8.8.8',nl_ip='9.9.9.9',vpn_net='10.77.0.0/24',gre_net='10.78.0.0/30',ovpn_port=1194,routing_mode='split',auth_mode='password'),'ru')
 namespace={'__name__':'test_payload'}
 fake=types.SimpleNamespace(LOCK_EX=2,flock=lambda *a:None)
 with patch.dict(sys.modules,{'fcntl':fake}):exec(compile(code,str(path),'exec'),namespace)
 return types.SimpleNamespace(**namespace),namespace

class CertificateManager(unittest.TestCase):
 def setUp(self):
  self.api,self.ns=load('ru/usr/local/sbin/ovpn-cert-manage.py');self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);root=pathlib.Path(self.temp.name)
  self.ns.update(CERT=root/'cert.pem',KEY=root/'key.pem',LINEAGE=root/'lineage.conf',STATUS=root/'status'/'status.json')
  self.ns['LINEAGE'].write_text('fixture managed lineage');self.ns['CERT'].write_text('fixture public certificate');self.ns['KEY'].write_text('fixture key, not real')
 def result(self,code=0,out=''):return types.SimpleNamespace(returncode=code,stdout=out,stderr='')
 def manage(self,action):
  with contextlib.redirect_stdout(io.StringIO()):return self.api.manage(action)
 def test_reuse_skips_network_and_certbot(self):
  self.ns['reusable']=lambda:True;self.ns['transport']=Mock(side_effect=AssertionError('No network'))
  with patch('subprocess.run',side_effect=AssertionError('No certbot')):self.assertEqual(self.manage('ensure'),0)
  self.assertEqual(json.loads(self.ns['STATUS'].read_text())['status'],'reused')
 def test_missing_key_cannot_be_reused(self):self.ns['KEY'].unlink();self.assertFalse(self.api.reusable())
 def test_unmanaged_certificate_not_silently_reused(self):self.ns['LINEAGE'].unlink();self.assertFalse(self.api.reusable())
 def test_valid_trusted_matching_certificate(self):
  self.ns['command']=lambda args,**kw:self.result(out=b'PUBLIC-DER')
  self.assertTrue(self.api.reusable())
 def test_wrong_ip_rejected(self):
  self.ns['command']=lambda args,**kw:self.result(1 if '-checkip' in args else 0,b'PUB')
  self.assertFalse(self.api.reusable())
 def test_expiring_certificate_rejected(self):
  self.ns['command']=lambda args,**kw:self.result(1 if '-checkend' in args else 0,b'PUB')
  self.assertFalse(self.api.reusable())
 def test_untrusted_certificate_rejected(self):
  self.ns['command']=lambda args,**kw:self.result(1 if 'verify' in args else 0,b'PUB')
  self.assertFalse(self.api.reusable())
 def test_mismatched_key_rejected(self):
  self.ns['command']=lambda args,**kw:self.result(out=b'OTHER' if '-pubout' in args else b'PUBLIC')
  self.assertFalse(self.api.reusable())
 def test_proxy_environment_has_no_inherited_bypass(self):
  with patch.dict(os.environ,{'https_proxy':'old','NO_PROXY':'*','ALL_PROXY':'old'}):
   env=self.api.environment('nl');self.assertEqual(env['HTTPS_PROXY'],self.ns['PROXY']);self.assertNotIn('NO_PROXY',env);self.assertNotIn('https_proxy',env)
   self.assertFalse(any(k.lower().endswith('_proxy') for k in self.api.environment('direct')))
 def test_renew_only_own_lineage_without_force(self):
  self.ns['transport']=lambda:'nl'
  with patch('subprocess.run',return_value=self.result()) as run:self.assertEqual(self.manage('renew'),0)
  args=run.call_args.args[0];self.assertIn('renew',args);self.assertIn('shortlived',args);self.assertIn('ovpn-links',args);self.assertIn('--deploy-hook',args);self.assertNotIn('--force-renewal',args);self.assertEqual(run.call_args.kwargs['env']['HTTPS_PROXY'],self.ns['PROXY'])
 def test_network_failure_keeps_keys_and_runs_no_certbot(self):
  self.ns['transport']=lambda:None
  with patch('subprocess.run',side_effect=AssertionError('No subprocess')):self.assertEqual(self.manage('renew'),1)
  self.assertTrue(self.ns['CERT'].is_file());self.assertTrue(self.ns['KEY'].is_file())
 def test_rate_limit_does_not_retry_or_delete_certificate(self):
  self.ns['transport']=lambda:'nl'
  with patch('subprocess.run',return_value=self.result(1,'rateLimited')) as run:self.assertEqual(self.manage('renew'),1)
  self.assertEqual(run.call_count,1);self.assertTrue(self.ns['CERT'].is_file())
 def test_timeout_retries_once_using_detected_transport(self):
  self.ns['transport']=Mock(side_effect=['nl','direct'])
  with patch('subprocess.run',side_effect=[subprocess.TimeoutExpired('certbot',300),self.result()]) as run:self.assertEqual(self.manage('renew'),0)
  self.assertEqual(run.call_count,2);self.assertNotIn('HTTPS_PROXY',run.call_args.kwargs['env'])
 def test_probe_is_non_mutating(self):
  self.ns['transport']=lambda:'nl';self.assertEqual(self.manage('probe'),0);self.assertFalse(self.ns['STATUS'].exists())
 def test_status_is_private(self):
  with contextlib.redirect_stdout(io.StringIO()):self.api.status('renew','ok','nl')
  if os.name!='nt':self.assertEqual(self.ns['STATUS'].stat().st_mode&0o777,0o600)
 def test_transport_falls_back_to_direct_with_tls_verification(self):
  response=Mock();response.status=200;response.read.return_value=b'{"newNonce":"nonce","newAccount":"account"}'
  opener=Mock();opener.open.side_effect=[OSError('unreachable'),contextlib.nullcontext(response)]
  with patch('urllib.request.build_opener',return_value=opener),patch('ssl.create_default_context',wraps=__import__('ssl').create_default_context) as tls:self.assertEqual(self.api.transport(),'direct')
  self.assertEqual(tls.call_count,2)

class AcmeRelay(unittest.TestCase):
 def setUp(self):self.api,self.ns=load('nl/usr/local/sbin/ovpn-acme-proxy.py')
 def test_only_acme_https_connect_allowed(self):self.assertEqual(self.api.parse_target('CONNECT acme-v02.api.letsencrypt.org:443 HTTP/1.1'),'acme-v02.api.letsencrypt.org')
 def test_arbitrary_targets_and_methods_rejected(self):
  for target in ('CONNECT example.com:443 HTTP/1.1','CONNECT acme-v02.api.letsencrypt.org:80 HTTP/1.1','GET / HTTP/1.1','CONNECT 127.0.0.1:443 HTTP/1.1','CONNECT acme-v02.api.letsencrypt.org.evil:443 HTTP/1.1'):
   with self.subTest(target=target),self.assertRaises(ValueError):self.api.parse_target(target)
 def test_private_dns_targets_never_connected(self):
  records=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',443)),(socket.AF_INET,socket.SOCK_STREAM,6,'',('10.0.0.1',443))]
  with patch('socket.getaddrinfo',return_value=records),patch('socket.socket') as connect,self.assertRaises(OSError):self.api.upstream('acme-v02.api.letsencrypt.org')
  connect.assert_not_called()
 def test_proxy_binds_only_tunnel_ip(self):self.assertEqual(self.api.BIND,'10.78.0.2');self.assertEqual(self.api.CLIENT,'10.78.0.1')
 def test_public_endpoint_is_connected_without_tls_interception(self):
  records=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443))]
  with patch('socket.getaddrinfo',return_value=records),patch('socket.socket') as make:self.api.upstream('acme-v02.api.letsencrypt.org');make.return_value.connect.assert_called_once_with(('8.8.8.8',443))

 def test_connect_relay_transfers_opaque_bytes_both_directions(self):
  client,accepted=socket.socketpair();remote,target=socket.socketpair()
  for sock in (client,accepted,remote,target):self.addCleanup(sock.close);sock.settimeout(2)
  self.ns['upstream']=lambda host:remote
  worker=threading.Thread(target=lambda:self.api.Handler(accepted,('10.78.0.1',12345),None),daemon=True)
  worker.start()
  try:
   client.sendall(b'CONNECT acme-v02.api.letsencrypt.org:443 HTTP/1.1\r\nHost: acme-v02.api.letsencrypt.org:443\r\n\r\n')
   self.assertIn(b'200 Connection Established',client.recv(1024))
   client.sendall(b'opaque TLS client bytes');self.assertEqual(target.recv(1024),b'opaque TLS client bytes')
   target.sendall(b'opaque TLS server bytes');self.assertEqual(client.recv(1024),b'opaque TLS server bytes')
  finally:client.close();worker.join(timeout=3)
  self.assertFalse(worker.is_alive())

class CertificateIntegration(unittest.TestCase):
 def test_timer_hourly_and_safe_hook(self):
  base=engine.ROOT/'payload/ru'
  timer=(base/'etc/systemd/system/ovpn-cert-renew.timer').read_text();self.assertIn('OnCalendar=hourly',timer);self.assertIn('Persistent=true',timer)
  hook=(base/'etc/letsencrypt/renewal-hooks/deploy/ovpn-nginx.sh').read_text();self.assertIn('set -e',hook);self.assertIn('reload nginx',hook);self.assertNotIn('restart',hook)
 def test_nl_proxy_is_stopped_during_rollback(self):self.assertIn("units=['ovpn-acme-proxy'",engine.ROLLBACK)
 def test_failed_install_resume_uses_saved_modes_only_when_allowed(self):
  ep=types.SimpleNamespace(python=lambda code:json.dumps({'profiles':[None,None],'list_classifier':False,'split_tools':False}))
  state={'version':2,'complete':False,'config':{'routing_mode':'split','auth_mode':'password'}}
  self.assertEqual(backend.installed_modes(ep,state)['routing'],'unknown')
  result=backend.installed_modes(ep,state,allow_incomplete=True);self.assertEqual(result['routing'],'split');self.assertEqual(result['source'],'saved-incomplete')
  state['complete']=True;self.assertEqual(backend.installed_modes(ep,state,allow_incomplete=True)['routing'],'unknown')

 def test_proxy_script_readable_by_restricted_service_user(self):
  files={};ep=types.SimpleNamespace(role='nl',write=lambda path,text,mode=0o600:files.update({path:(text,mode)}))
  config=dict(ru_ip='8.8.8.8',nl_ip='9.9.9.9',vpn_net='10.77.0.0/24',gre_net='10.78.0.0/30',ovpn_port=1194,routing_mode='split',auth_mode='password')
  engine.deploy(config,ep,'fixture-not-a-real-psk')
  self.assertEqual(files['/usr/local/sbin/ovpn-acme-proxy.py'][1],0o755)
  self.assertIn('User=nobody',files['/etc/systemd/system/ovpn-acme-proxy.service'][0])

 def test_new_proxy_diagnostic_names_service(self):
  self.assertIn('ovpn-acme-proxy',engine.diagnostic_message('VPNAI_DIAG:SERVICE:ovpn-acme-proxy'))
