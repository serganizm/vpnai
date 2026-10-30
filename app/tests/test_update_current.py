# -*- coding: utf-8 -*-
import copy,json,pathlib,sys,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import backend
from test_app import settings

class CurrentUpdate(unittest.TestCase):
 def run_update(self,existing=True,auth='password',routing='full_nl',revision='a'*64,failure=False,active=True):
  previous={'version':2,'complete':True,'config':backend.config(settings(initial_user='alice')),'psk':'fixture-key'}
  snapshot={'revision':'a'*64,'user_count':1 if existing else 0,'active_user_count':1 if existing and active else 0,'users':[{'name':'alice','enabled':True}] if existing else []}
  endpoints=[]
  class EP:
   def __init__(self,role,s):self.role=role;self.settings=s;self.files={};self.commands=[];self.calls=[];endpoints.append(self)
   def connect(self):pass
   def lock(self):pass
   def close(self):pass
   def inventory(self):return {'managed':True,'os':{},'swan':'active','reserved_files':[]}
   def write(self,path,text,mode=0o600,preserve=False):self.files[path]=(text,preserve)
   def shell(self,text,quiet=False):
    self.commands.append(text)
    return 'ubuntu\n24.04\n3.12\n' if text==backend.SYSTEM_INFO else ''
   def python(self,code,data=None):
    self.calls.append((code,data))
    if code==backend.UPDATE_PASSWORDS:return '{"generated":[]}'
    if code==backend.engine.INITIAL_USER_IF_EMPTY:return json.dumps({'name':data,'created':True})
    if 'state.json' in code:return json.dumps(copy.deepcopy(previous))
    return '{}'
  params=settings(action='resume',routing=routing,auth=auth,update_revision=revision,initial_user='newuser',ru_routes='8.8.4.4',eu_routes='1.1.1.1',vpn_port=21194)
  job=backend.Job(params)
  observed=[]
  def deploy(c,ep,psk):observed.append(copy.deepcopy(c))
  with patch.object(backend,'Remote',EP),patch.object(backend,'installed_modes',return_value={'routing':'split','auth':'password','legacy':False}),patch.object(backend,'update_configuration',return_value=snapshot),patch.object(backend,'backup_update',return_value={}) as backups,patch.object(backend.engine,'preflight'),patch.object(backend.engine,'install_packages'),patch.object(backend.engine,'deploy',side_effect=deploy),patch.object(backend.engine,'initialize_ru'),patch.object(backend.engine,'ensure_ipsec'),patch.object(backend.engine,'setup_https',return_value={}),patch.object(backend.engine,'verify',side_effect=backend.UserError('failed verification') if failure else None,return_value={}),patch.object(backend,'collect',return_value=b'profiles'):
   job.run()
  return job,endpoints,observed,backups
 def test_update_applies_modes_port_lists_without_creating_user(self):
  job,endpoints,configs,backups=self.run_update()
  self.assertEqual(job.status,'success',job.events);backups.assert_called_once()
  for c in configs:self.assertEqual((c['routing_mode'],c['auth_mode'],c['ovpn_port'],c['initial_user']),('full_nl','password',21194,''))
  ru=endpoints[0];self.assertEqual(ru.files['/etc/ovpn-routing/force-ru.txt'],('8.8.4.4/32\n',False));self.assertEqual(ru.files['/etc/ovpn-routing/extra-nl.txt'],('1.1.1.1/32\n',False))
  self.assertFalse(any(code in (backend.engine.INITIAL_USER,backend.engine.INITIAL_USER_IF_EMPTY) for code,_ in ru.calls))
  self.assertTrue(all(any('restart ovpn-network ovpn-tcp-network' in c for c in ep.commands) for ep in endpoints))
 def test_certificate_mode_and_no_password_changes(self):
  job,endpoints,configs,_=self.run_update(auth='certificate',routing='full_mixed');self.assertEqual(job.status,'success',job.events)
  self.assertEqual(configs[0]['auth_mode'],'certificate');self.assertFalse(any(code==backend.UPDATE_PASSWORDS for code,_ in endpoints[0].calls))
 def test_empty_database_creates_one_user_conditionally(self):
  job,endpoints,_,_=self.run_update(existing=False);self.assertEqual(job.status,'success',job.events)
  self.assertIn((backend.engine.INITIAL_USER_IF_EMPTY,'newuser'),endpoints[0].calls)
 def test_disabled_users_preserved_without_creating_or_exporting(self):
  job,endpoints,configs,_=self.run_update(active=False)
  self.assertEqual(job.status,'success',job.events);self.assertEqual(configs[0]['initial_user'],'');self.assertIsNone(job.artifact)
 def test_stale_config_stops_before_backups_or_writes(self):
  job,endpoints,configs,backups=self.run_update(revision='b'*64);self.assertEqual(job.status,'error');backups.assert_not_called();self.assertFalse(configs);self.assertFalse(any(e.files for e in endpoints))
 def test_missing_loaded_config_stops(self):
  job,endpoints,configs,backups=self.run_update(revision='');self.assertEqual(job.status,'error');self.assertFalse(configs);backups.assert_not_called()
 def test_failed_update_does_not_delete_existing_installation(self):
  job,endpoints,_,_=self.run_update(failure=True);self.assertEqual(job.status,'error')
  self.assertFalse(any('|| /usr/local/sbin/ovpn-install-rollback' in c for e in endpoints for c in e.commands))
  self.assertTrue(any('Защитные архивы' in event['message'] for event in job.events))

class ReadConfiguration(unittest.TestCase):
 def test_snapshot_public_data_normalized_and_versioned(self):
  raw={'state':True,'config':{'ru_ip':'8.8.8.8','nl_ip':'9.9.9.9','ovpn_port':1194},'users':[{'name':'alice','enabled':True}],'ru_routes':'8.8.4.4\n','eu_routes':'# comment\n1.1.1.1/32\n'}
  class EP:
   def python(self,code,data=None):return json.dumps(raw)
  with patch.object(backend,'installed_modes',return_value={'routing':'split','auth':'certificate'}):
   value=backend.update_configuration(EP(),settings(),{})
   self.assertEqual(value['ru_routes'],['8.8.4.4/32']);self.assertEqual(value['config']['auth_mode'],'certificate');self.assertEqual(len(value['revision']),64)
   raw['eu_routes']='1.0.0.1'
   self.assertNotEqual(value['revision'],backend.update_configuration(EP(),settings(),{})['revision'])
