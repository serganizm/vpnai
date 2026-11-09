"""EU SSH via RU jump host: target selection, channel open, fingerprint path."""
import pathlib,socket,sys,types,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import backend

def settings(**extra):
    base={'demo':False,'action':'check','ru':{'host':'8.8.8.8','port':22,'password':'PRIVATE-RU'},'nl':{'host':'9.9.9.9','port':2222,'password':'PRIVATE-NL'}}
    base.update(extra);return backend.validate(base)

class EuJumpValidate(unittest.TestCase):
    def test_default_direct_public(self):
        s=settings();self.assertEqual(s['eu_ssh'],'direct');self.assertEqual(s['eu_target'],'public')
    def test_via_ru_gre(self):
        s=settings(eu_ssh='via_ru',eu_target='gre');self.assertEqual(s['eu_ssh'],'via_ru');self.assertEqual(s['eu_target'],'gre')
    def test_direct_forces_public_target(self):
        s=settings(eu_ssh='direct',eu_target='gre');self.assertEqual(s['eu_target'],'public')
    def test_bad_mode_rejected(self):
        with self.assertRaises(backend.UserError):settings(eu_ssh='proxy')
    def test_connect_target(self):
        direct=settings();self.assertEqual(backend.eu_connect_target(direct),('9.9.9.9',2222))
        via=settings(eu_ssh='via_ru',eu_target='public');self.assertEqual(backend.eu_connect_target(via),('9.9.9.9',2222))
        gre=settings(eu_ssh='via_ru',eu_target='gre');self.assertEqual(backend.eu_connect_target(gre),(backend.GRE_EU_HOST,2222))

class EuJumpRemote(unittest.TestCase):
    def test_make_remote_direct_has_no_jump(self):
        ep=backend.make_remote('nl',settings());self.assertIsNone(ep.jump);self.assertEqual(ep.connect_host,'9.9.9.9')
    def test_make_remote_via_ru_uses_jump_and_gre(self):
        s=settings(eu_ssh='via_ru',eu_target='gre');s['ru']['fingerprint']='SHA256:'+'A'*43;s['nl']['fingerprint']='SHA256:'+'B'*43
        ep=backend.make_remote('nl',s);self.assertEqual(ep.jump['host'],'8.8.8.8');self.assertEqual(ep.connect_host,backend.GRE_EU_HOST);self.assertEqual(ep.connect_port,2222);self.assertEqual(ep.host,'9.9.9.9')
    def test_fingerprints_via_ru_opens_channel_not_direct_eu(self):
        s=settings(eu_ssh='via_ru',eu_target='public');calls=[];channels=[]
        class Transport:
            def __init__(self,sock):self.sock=sock
            def start_client(self,timeout):calls.append(('handshake',getattr(self.sock,'label','sock')))
            def get_remote_server_key(self):return types.SimpleNamespace(asbytes=lambda:b'eu-key' if getattr(self.sock,'label',None)=='eu' else b'ru-key')
            def close(self):pass
            def set_keepalive(self,n):pass
            def open_channel(self,kind,dest,local,timeout=None):
                calls.append(('channel',kind,dest));ch=types.SimpleNamespace(label='eu',close=lambda:None);channels.append(ch);return ch
        class Client:
            def __init__(self):self._transport=None
            def set_missing_host_key_policy(self,policy):self.policy=policy
            def connect(self,**kw):
                calls.append(('auth',kw['hostname'],kw['port']));sock=types.SimpleNamespace(label='jump');self._transport=Transport(sock)
                key=types.SimpleNamespace(asbytes=lambda:b'ru-key');self.policy.missing_host_key(self,kw['hostname'],key)
            def get_transport(self):return self._transport
            def close(self):calls.append(('close',))
        def create_connection(addr,timeout=None):
            calls.append(('tcp',addr));sock=types.SimpleNamespace(label='ru-direct',close=lambda:None);return sock
        pm=types.SimpleNamespace(Transport=Transport,SSHClient=Client,MissingHostKeyPolicy=type('MissingHostKeyPolicy',(),{}),Ed25519Key=object,ECDSAKey=object,RSAKey=object,AuthenticationException=type('AuthenticationException',(Exception,),{}))
        with patch.object(backend,'get_paramiko',return_value=pm),patch.object(socket,'create_connection',side_effect=create_connection):
            result=backend.fingerprints(s)
        self.assertEqual(set(result),{'ru','nl'})
        self.assertIn(('tcp',('8.8.8.8',22)),calls)
        self.assertNotIn(('tcp',('9.9.9.9',2222)),calls)
        self.assertIn(('channel','direct-tcpip',('9.9.9.9',2222)),calls)
        self.assertTrue(any(c[0]=='auth' and c[1]=='8.8.8.8' for c in calls))

if __name__=='__main__':unittest.main()
