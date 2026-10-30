# -*- coding: utf-8 -*-
import json,pathlib,sys,tempfile,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import app,backend,ssh_aliases

class AliasConfig(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def write(self,name,text):
        p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text);return p
    def test_windows_paths(self):
        paths=ssh_aliases.config_paths('win32',{'USERPROFILE':'C:/Users/Alice','PROGRAMDATA':'D:/Shared'},'/unused')
        self.assertEqual(paths,[pathlib.Path('C:/Users/Alice/.ssh/config'),pathlib.Path('D:/Shared/ssh/ssh_config')])
    def test_unix_paths(self):
        for platform in ('darwin','linux'):
            self.assertEqual(ssh_aliases.config_paths(platform,{},'/users/alice'),[pathlib.Path('/users/alice/.ssh/config'),pathlib.Path('/etc/ssh/ssh_config')])
    def test_alias_include_defaults_and_negation(self):
        p=self.write('config','Include conf/*.conf\nHost * !eu\n Port 2200\nHost *\n User root\n Port 22\n')
        self.write('conf/servers.conf','Host ru ru-other\n HostName=8.8.8.8\n IdentityFile "~/key with spaces"\nHost eu\n HostName 1.1.1.1\n')
        aliases={a['alias']:a for a in ssh_aliases.catalog([p])['aliases']}
        self.assertEqual(set(aliases),{'ru','ru-other','eu'})
        self.assertEqual(aliases['ru']['port'],2200);self.assertEqual(aliases['eu']['port'],22)
        self.assertEqual(aliases['ru']['method'],'local-key');self.assertIn('key with spaces',aliases['ru']['key_path'])
    def test_user_first_value_wins_over_system(self):
        user=self.write('user','Host ru\n HostName 8.8.8.8\n Port 2222\n');system=self.write('system','Host *\n Port 22\n')
        self.assertEqual(ssh_aliases.catalog([user,system])['aliases'][0]['port'],2222)
    def test_windows_key_path_keeps_backslashes(self):
        p=self.write('config','Host ru\n HostName 8.8.8.8\n IdentityFile "C:\\Users\\Alice\\.ssh\\id_ed25519"\n')
        self.assertEqual(ssh_aliases.catalog([p])['aliases'][0]['key_path'],r'C:\Users\Alice\.ssh\id_ed25519')
    def test_proxy_and_nonroot_disabled(self):
        p=self.write('config','Host proxy\n HostName 8.8.8.8\n ProxyCommand malicious-command\nHost other\n HostName 1.1.1.1\n User alice\n')
        for a in ssh_aliases.catalog([p])['aliases']:self.assertTrue(a['disabled'])
    def test_match_exec_never_runs(self):
        p=self.write('config','Host ru\n HostName 8.8.8.8\nMatch exec "touch sentinel"\n User root\n')
        with patch('subprocess.run',side_effect=AssertionError('must not run')):
            result=ssh_aliases.catalog([p]);self.assertTrue(result['aliases'][0]['disabled'])
    def test_include_cycle_bounded(self):
        p=self.write('config','Include config\nHost ru\n HostName 8.8.8.8\n')
        self.assertTrue(ssh_aliases.catalog([p])['warnings'])
    def test_resolve_public_ipv4_no_dns(self):
        item={'alias':'ru','host':'8.8.8.8','port':22,'disabled':False}
        with patch.object(ssh_aliases,'catalog',return_value={'aliases':[item]}),patch('socket.getaddrinfo') as dns:
            self.assertEqual(ssh_aliases.resolve_alias('ru')['host'],'8.8.8.8');dns.assert_not_called()
    def test_resolve_dns_and_private_rejection(self):
        item={'alias':'ru','host':'host.example','port':22,'disabled':False}
        with patch.object(ssh_aliases,'catalog',return_value={'aliases':[item]}),patch('socket.getaddrinfo',return_value=[(None,None,None,None,('8.8.8.8',22))]):
            self.assertEqual(ssh_aliases.resolve_alias('ru')['host'],'8.8.8.8')
        item['host']='127.0.0.1'
        with patch.object(ssh_aliases,'catalog',return_value={'aliases':[item]}),self.assertRaises(backend.UserError):ssh_aliases.resolve_alias('ru')
    def test_ambiguous_dns_rejected(self):
        item={'alias':'ru','host':'host.example','port':22,'disabled':False}
        with patch.object(ssh_aliases,'catalog',return_value={'aliases':[item]}),patch('socket.getaddrinfo',return_value=[(None,None,None,None,('8.8.8.8',22)),(None,None,None,None,('1.1.1.1',22))]),self.assertRaises(backend.UserError):ssh_aliases.resolve_alias('ru')
    def test_no_literal_aliases_for_patterns(self):
        p=self.write('config','Host * !secret *.example\n Port 22\n')
        self.assertEqual(ssh_aliases.catalog([p])['aliases'],[])

class ConnectionSession(unittest.TestCase):
    def setUp(self):self.application=app.Application();self.admin=self.application.admin
    def tearDown(self):self.application.close()
    def test_incomplete_fields_and_secret_survive_reads_without_network(self):
        draft={'ru':{'host':'','password':'PRIVATE','user':'root','alias':'ru'},'nl':{'host':'1.1.1.1'}}
        with patch.object(backend,'Remote',side_effect=AssertionError('No network')):
            self.admin.dispatch('save-connection-session',{'draft':draft,'revision':10})
            value=self.admin.dispatch('connection-session',{})
        self.assertEqual(value['draft'],draft)
        value['draft']['ru']['password']='changed'
        self.assertEqual(self.admin.dispatch('connection-session',{})['draft']['ru']['password'],'PRIVATE')
    def test_late_save_cannot_overwrite_newer_password(self):
        for revision,password in [(10,'new'),(9,'old')]:self.admin.dispatch('save-connection-session',{'draft':{'ru':{'password':password}},'revision':revision})
        self.assertEqual(self.admin.connection_session()['draft']['ru']['password'],'new')
    def test_disconnect_preserves_session_but_app_close_clears(self):
        self.admin.connection_session({'ru':{'password':'PRIVATE'}})
        self.admin.dispatch('disconnect',{})
        self.assertEqual(self.admin.connection_session()['draft']['ru']['password'],'PRIVATE')
        self.application.close();self.assertEqual(self.admin.draft,{})
    def test_new_app_empty(self):self.assertEqual(self.admin.connection_session()['draft'],{})
    def test_bad_session_inputs(self):
        for value in ([],{'draft':[],'revision':1},{'draft':{},'revision':True},{'draft':{},'revision':-1}):
            with self.assertRaises(backend.UserError):self.admin.dispatch('save-connection-session',value)

if __name__=='__main__':unittest.main()
