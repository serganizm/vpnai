# -*- coding: utf-8 -*-
import os
import base64, copy, hashlib, io, json, pathlib, sys, tempfile, threading, unittest, urllib.error, urllib.request, zipfile
from unittest.mock import patch, Mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import app, backend, admin_backend, admin_remote

class Service(unittest.TestCase):
    def setUp(self):
        self.application=app.Application();self.admin=self.application.admin
        self.admin.settings={'ru':{'host':'8.8.8.8'},'nl':{'host':'1.1.1.1'}}
    def tearDown(self):self.application.close()
    def test_no_connection_blocks_operations(self):
        self.admin.close()
        with self.assertRaises(backend.UserError):self.admin.dispatch('create',{'name':'user','comment':''})
    def test_username_injection_rejected(self):
        with patch.object(self.admin,'remote') as remote:
            for name in ('../../root','x;id','$(id)','a\nwhoami','',None):
                with self.assertRaises(backend.UserError):self.admin.dispatch('credentials',{'name':name})
            remote.assert_not_called()
    def test_password_constraints(self):
        with patch.object(self.admin,'remote') as remote:
            for password in ('short','x'*257,'abcd1234\n','abcd1234\x00'):
                with self.assertRaises(backend.UserError):self.admin.dispatch('update',{'name':'user','password':password})
            remote.assert_not_called()
    def test_empty_password_preserves_password(self):
        with patch.object(self.admin,'remote',return_value={'updated':True}) as remote:
            self.admin.dispatch('update',{'name':'user','comment':'Phone','password':''})
            self.assertEqual(remote.call_args.kwargs['password'],'')
    def test_delete_requires_exact_confirmation(self):
        with patch.object(self.admin,'remote') as remote:
            with self.assertRaises(backend.UserError):self.admin.dispatch('delete',{'name':'user','confirmation':'other'})
            remote.assert_not_called()
    def test_comment_validation(self):
        for value in ('a'*201,'a\nb',{},None):
            with self.assertRaises(backend.UserError):self.admin.dispatch('update',{'name':'user','comment':value})
    def test_route_server_ip_and_private_network_rejected(self):
        for cidr in ('8.8.8.0/24','192.168.0.0/16','::1','0.0.0.0/0'):
            with self.assertRaises(backend.UserError):self.admin.dispatch('route-change',{'kind':'eu','action':'add','cidr':cidr})
    def test_route_normalized(self):
        with patch.object(self.admin,'remote',return_value={}) as remote:
            self.admin.dispatch('route-change',{'kind':'ru','action':'add','cidr':'9.9.9.10/24'})
            self.assertEqual(remote.call_args.kwargs['cidr'],'9.9.9.0/24')
    def test_install_job_blocks_admin(self):
        self.application.jobs={'job':Mock(status='running')}
        with self.assertRaises(backend.UserError):self.admin.dispatch('status',{})
        self.application.jobs={}
    def test_remote_requires_pinned_transport_and_closes(self):
        settings={'ru':{'host':'8.8.8.8','fingerprint':'pin'},'nl':{'host':'1.1.1.1'}}
        original=copy.deepcopy(settings)
        with patch.object(backend,'Remote') as transport:
            ep=transport.return_value;ep.python.return_value=json.dumps({'ok':True,'result':{'done':True}})
            self.assertTrue(self.admin.remote('ru','routes',settings=settings)['done'])
            ep.connect.assert_called_once();ep.lock.assert_called_once();ep.close.assert_called_once()
        self.assertEqual(settings,original)
    def test_remote_failure_closes(self):
        with patch.object(backend,'Remote') as transport:
            ep=transport.return_value;ep.connect.side_effect=backend.UserError('key changed')
            with self.assertRaises(backend.UserError):self.admin.remote('ru','routes')
            ep.close.assert_called_once()
    def test_close_forgets_credentials(self):
        old=self.admin.settings;self.admin.close()
        self.assertEqual(old['ru'],{});self.assertIsNone(self.admin.settings)

@unittest.skipUnless(os.name=='posix','Server payload execution requires Unix file locking')
class RemoteOperations(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temp.name)
        self.base=self.root/'server';self.base.mkdir();self.profiles=self.root/'profiles';self.profiles.mkdir()
        self.db={'alice':{'enabled':True,'comment':'Old','salt':'00'*16,'hash':hashlib.pbkdf2_hmac('sha256',b'password123',bytes(16),300000).hex()}}
        (self.base/'users.json').write_text(json.dumps(self.db));(self.profiles/'alice-credentials.txt').write_text('Login: alice\nPassword: password123\n')
        source=pathlib.Path(admin_remote.__file__).read_text().replace("'/etc/openvpn/server'",repr(str(self.base))).replace("'/root/ovpn-profiles'",repr(str(self.profiles))).replace("'/run/ovpn-user.lock'",repr(str(self.root/'user.lock')))
        namespace={'__name__':'remote_test'};exec(compile(source,'remote_test','exec'),namespace);self.execute=namespace['execute']
    def tearDown(self):self.temp.cleanup()
    def test_credentials_validate_hash(self):
        self.assertEqual(self.execute({'operation':'credentials','name':'alice'})['password'],'password123')
        (self.profiles/'alice-credentials.txt').write_text('Password: incorrect\n')
        self.assertIsNone(self.execute({'operation':'credentials','name':'alice'})['password'])
    def test_comment_update_no_password_command(self):
        with patch('subprocess.run') as command:
            self.execute({'operation':'update','name':'alice','comment':'New','password':''});command.assert_not_called()
        self.assertEqual(json.loads((self.base/'users.json').read_text())['alice']['comment'],'New')
        self.assertEqual((self.base/'users.json').stat().st_mode&0o777,0o600)
    def test_password_passed_on_stdin(self):
        with patch('subprocess.run',return_value=Mock(returncode=0,stdout='')) as command:
            self.execute({'operation':'update','name':'alice','comment':'Phone','password':'pAss$(id)123'})
            self.assertEqual(command.call_args.args[0],['/usr/local/sbin/ovpn-user','passwd','alice'])
            self.assertEqual(command.call_args.kwargs['input'],'pAss$(id)123\n')
    def test_export_only_requested_user_and_safe_filenames(self):
        for suffix in ('-UDP.ovpn','-TCP.ovpn'):(self.profiles/('alice'+suffix)).write_text('client\n')
        result=self.execute({'operation':'profiles','name':'alice'})
        with zipfile.ZipFile(io.BytesIO(base64.b64decode(result['archive']))) as archive:
            self.assertEqual(set(archive.namelist()),{'alice-UDP.ovpn','alice-TCP.ovpn','alice-credentials.txt'})
    def test_export_rejects_symlink(self):
        (self.profiles/'alice-UDP.ovpn').symlink_to(self.base/'users.json');(self.profiles/'alice-TCP.ovpn').write_text('client')
        with self.assertRaises(ValueError):self.execute({'operation':'profiles','name':'alice'})

class API(unittest.TestCase):
    def setUp(self):
        self.application=app.Application();self.server=app.Server(('127.0.0.1',0),self.application)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.url='http://127.0.0.1:'+str(self.server.server_port)
    def tearDown(self):self.server.shutdown();self.server.server_close();self.application.close();self.thread.join()
    def request(self,path,data,authorized=True,origin=None):
        headers={'Content-Type':'application/json'}
        if authorized:headers['X-Local-Token']=self.application.token
        if origin:headers['Origin']=origin
        req=urllib.request.Request(self.url+path,json.dumps(data).encode(),headers,method='POST')
        try:
            with urllib.request.urlopen(req) as response:return response.status,response.read()
        except urllib.error.HTTPError as error:return error.code,error.read()
    def test_admin_requires_auth_and_same_origin(self):
        with patch.object(self.application.admin,'dispatch') as dispatch:
            self.assertEqual(self.request('/api/admin/status',{},False)[0],403)
            self.assertEqual(self.request('/api/admin/status',{},origin='https://evil.example')[0],403)
            dispatch.assert_not_called()
    def test_empty_status_and_no_ssh(self):
        with patch.object(backend,'Remote') as remote:
            code,body=self.request('/api/admin/status',{})
            self.assertEqual(code,200);self.assertFalse(json.loads(body)['connected']);remote.assert_not_called()
    def test_invalid_payload(self):self.assertEqual(self.request('/api/admin/create',[])[0],400)
    def test_live_mutations_require_connection(self):self.assertEqual(self.request('/api/admin/update',{'name':'alice','password':'12345678'})[0],400)
    def test_zip_response(self):
        with patch.object(self.application.admin,'dispatch',return_value={'archive':base64.b64encode(b'ZIP').decode()}):
            self.assertEqual(self.request('/api/admin/profiles',{'name':'alice'}),(200,b'ZIP'))


    def test_connection_session_api_roundtrip_and_no_network(self):
        with patch.object(backend,'Remote',side_effect=AssertionError('No SSH')):
            draft={'ru':{'host':'8.8.8.8','password':'PRIVATE','alias':'ru'}}
            code,body=self.request('/api/admin/save-connection-session',{'draft':draft,'revision':100})
            self.assertEqual(code,200)
            code,body=self.request('/api/admin/connection-session',{})
            self.assertEqual(json.loads(body)['draft']['ru']['password'],'PRIVATE')
            self.assertEqual(self.request('/api/admin/connection-session',{},False)[0],403)
    def test_alias_list_requires_token(self):
        with patch.object(app.ssh_aliases,'catalog',side_effect=AssertionError('must not read config')):
            try:urllib.request.urlopen(self.url+'/api/ssh/aliases')
            except urllib.error.HTTPError as error:self.assertEqual(error.code,403)
            else:self.fail('Aliases exposed without authentication')
    def test_alias_resolution_requires_token(self):
        with patch.object(app.ssh_aliases,'resolve_alias',side_effect=AssertionError('must not resolve')):
            self.assertEqual(self.request('/api/ssh/alias',{'alias':'ru'},False)[0],403)

    def test_update_configuration_api_requires_trust_before_ssh(self):
        with patch.object(app.backend,'read_update_configuration',side_effect=AssertionError('No SSH')):
            data={'ru':{'host':'8.8.8.8','password':'secret'},'nl':{'host':'9.9.9.9','password':'secret'}}
            self.assertEqual(self.request('/api/update-config',data,False)[0],403)
            self.assertEqual(self.request('/api/update-config',data)[0],400)

if __name__=='__main__':unittest.main()
