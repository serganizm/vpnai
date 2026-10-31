#!/usr/bin/python3
"""Dedicated DNS policy routing. Called locally on RU by systemd; no credentials."""
import ipaddress,json,pathlib,subprocess,sys
TABLE=31220
PRIORITY=10220
SETTINGS='/etc/ovpn-routing/dns.json'
def run(args,check=True):
 r=subprocess.run(args,capture_output=True,text=True,timeout=15)
 if check and r.returncode:raise ValueError('Не удалось настроить маршрутизацию DNS.')
 return r

def rules(config):
 return {(str(ipaddress.ip_network(net)),str(ipaddress.ip_network(ip+'/32')),TABLE) for net in config.get('networks',[]) for ip in config.get('servers',[])}

def rule_key(item):
 def network(field):
  address=item.get(field,'0.0.0.0/0')
  if address=='all':address='0.0.0.0/0'
  length=item.get(field+'len')
  if '/' not in address and length is not None:address+='/'+str(length)
  return str(ipaddress.ip_network(address,strict=False))
 if set(item)-{'priority','src','srclen','dst','dstlen','table','protocol'}:raise ValueError('Приоритет DNS занят другим правилом.')
 return (network('src'),network('dst'),int(item.get('table',-1)))

def inspect(config):
 allowed=rules(config)|{tuple(x) for x in config.get('previous_rules',[])}
 current=json.loads(run(['ip','-j','rule','show']).stdout)
 for item in current:
  if not 0<item.get('priority',0)<PRIORITY:continue
  # strongSwan leaves its standard lookup rule present even with no routes.
  # An empty table cannot capture DNS traffic; leave this rule untouched.
  standard_ipsec=(item.get('priority')==220 and str(item.get('table'))=='220' and item.get('src','all')=='all' and item.get('dst','all')=='all' and set(item)<= {'priority','src','dst','table','protocol'})
  if standard_ipsec:
   early=run(['ip','-j','route','show','table','220'],False)
   missing=early.returncode==2 and 'FIB table does not exist' in getattr(early,'stderr','')
   if (early.returncode==0 or missing) and not json.loads(early.stdout or '[]'):continue
  raise ValueError('Более ранние правила маршрутизации требуют ручной проверки перед настройкой DNS.')
 existing=[]
 for item in current:
  if item.get('priority')!=PRIORITY:continue
  try:key=rule_key(item)
  except (ValueError,TypeError):raise ValueError('Приоритет DNS занят другим правилом.')
  if key not in allowed or any(k in item for k in ('fwmark','iif','oif')):raise ValueError('Приоритет DNS занят другим правилом.')
  existing.append(key)
 table=run(['ip','-j','route','show','table',str(TABLE)],False)
 entries=json.loads(table.stdout or '[]')
 for entry in entries:
  if entry.get('dst')!='default' or (entry.get('type')!='unreachable' and entry.get('dev')!=config['interface']):raise ValueError('Таблица DNS занята чужими маршрутами.')
 return existing

def apply(config,clear=False):
 if config.get('version')!=1:raise ValueError('Неизвестный формат DNS.')
 existing=inspect(config)
 for net,ip,table in existing:run(['ip','rule','del','priority',str(PRIORITY),'from',net,'to',ip,'table',str(table)])
 run(['ip','route','flush','table',str(TABLE)],False)
 if clear or not config.get('servers'):return
 # Unreachable fallback prevents falling back to the main table if GRE is unavailable.
 run(['ip','route','replace','unreachable','default','metric','32760','table',str(TABLE)])
 run(['ip','route','replace','default','via',config['gateway'],'dev',config['interface'],'metric','10','table',str(TABLE)])
 for net,ip,table in sorted(rules(config)):
  run(['ip','rule','add','priority',str(PRIORITY),'from',net,'to',ip,'table',str(table)])
 run(['ip','route','flush','cache'],False)

if __name__=='__main__':
 p=pathlib.Path(SETTINGS)
 if p.exists():apply(json.loads(p.read_text()),clear=len(sys.argv)>1 and sys.argv[1]=='clear')
 elif any('# VPNAI DNS BEGIN' in conf.read_text() for conf in pathlib.Path('/etc/openvpn/server').glob('ru*.conf')):raise SystemExit('Настройки DNS отсутствуют, но DNS включён в OpenVPN. Проверьте резервную копию.')
