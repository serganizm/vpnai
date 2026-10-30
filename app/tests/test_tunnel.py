# -*- coding: utf-8 -*-
import json,pathlib,sys,subprocess,unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from admin_remote import tunnel_status

class Tunnel(unittest.TestCase):
 def setUp(self):self.config={'gre_net':'10.78.0.0/30','nl_ip':'8.8.8.8'}
 def command(self,args,**kwargs):
  if args[0]=='ip':return Mock(returncode=0,stdout=json.dumps([{'flags':['UP'],'linkinfo':{'info_kind':'gre','info_data':{'remote':'8.8.8.8'}}}]))
  if args[0]=='swanctl':return Mock(returncode=0,stdout="ovpn-gre: #1, ESTABLISHED, IKEv2\n  remote '8.8.8.8' @ 8.8.8.8[4500]\n  gre: #2, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16\n")
  self.assertEqual(args,['ping','-n','-c','1','-W','2','-I','gre-nl','10.78.0.2'])
  return Mock(returncode=0,stdout='64 bytes from 10.78.0.2: icmp_seq=1 ttl=64 time=38.5 ms\n')
 def test_healthy_peer_ipsec_and_latency(self):
  with patch('subprocess.run',side_effect=self.command) as run:
   status=tunnel_status(self.config,'8.8.8.8');self.assertEqual(status['state'],'up');self.assertEqual(status['latency_ms'],38.5);self.assertEqual(run.call_count,3)
 def test_config_mismatch_performs_no_commands(self):
  with patch('subprocess.run') as run:
   self.assertEqual(tunnel_status(self.config,'1.1.1.1')['state'],'unknown');run.assert_not_called()
 def test_missing_config_performs_no_commands(self):
  with patch('subprocess.run') as run:
   self.assertEqual(tunnel_status({})['state'],'unknown');run.assert_not_called()
 def test_interface_missing(self):
  with patch('subprocess.run',return_value=Mock(returncode=1)):
   self.assertEqual(tunnel_status(self.config)['state'],'down')
 def test_ipsec_missing_does_not_claim_success(self):
  def command(args,**kw):return Mock(returncode=0,stdout='') if args[0]=='swanctl' else self.command(args,**kw)
  with patch('subprocess.run',side_effect=command):self.assertEqual(tunnel_status(self.config)['state'],'down')
 def test_ping_failure_is_down(self):
  def command(args,**kw):return Mock(returncode=1,stdout='') if args[0]=='ping' else self.command(args,**kw)
  with patch('subprocess.run',side_effect=command):self.assertEqual(tunnel_status(self.config)['state'],'down')
 def test_timeout_is_unknown(self):
  with patch('subprocess.run',side_effect=subprocess.TimeoutExpired('ip',4)):
   self.assertEqual(tunnel_status(self.config)['state'],'unknown')
