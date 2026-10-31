"""Read-only runtime diagnostics, independent of installer ownership metadata."""
import json

RUNTIME = r'''
import json,pathlib,subprocess,re,ipaddress
checks=[]
def record(name,passed,detail):checks.append({'check':name,'passed':passed,'detail':detail})
def command(args):
 try:
  r=subprocess.run(args,capture_output=True,text=True,timeout=8)
  return r.returncode,r.stdout
 except (OSError,subprocess.TimeoutExpired):return None,''
role,peer=DATA['role'],DATA['peer']
code,out=command(['sysctl','-n','net.ipv4.ip_forward'])
record('Пересылка IPv4',None if code!=0 else out.strip()=='1','net.ipv4.ip_forward='+out.strip() if code==0 else 'Состояние недоступно')
if role=='ru':
 configs=list(pathlib.Path('/etc/openvpn/server').glob('*.conf'))+list(pathlib.Path('/etc/openvpn').glob('*.conf'))
 configs=[p for p in configs if re.search(r'^\s*(?:server|server-bridge)\s',p.read_text(errors='replace'),re.M)]
 record('Конфигурации OpenVPN',bool(configs),'Найдено серверных конфигураций: '+str(len(configs)))
 for p in configs:
  # Never return configuration contents: they may contain credentials.
  text=p.read_text(errors='replace');values={}
  for line in text.splitlines():
   fields=line.split('#',1)[0].split(';',1)[0].split()
   if len(fields)>1 and fields[0] in ('port','proto'):values[fields[0]]=fields[1]
   if len(fields)>2 and fields[0]=='server':values['network']='/'.join(fields[1:3])
  if 'network' in values:
   try:
    network=ipaddress.ip_network(values['network'],strict=False)
    code,out=command(['ip','-j','-4','route','show'])
    routes=json.loads(out) if code==0 else None
    present=any(r.get('dst')==str(network) for r in (routes or []))
    record('Маршрут VPN '+p.stem,None if routes is None else present,str(network))
   except ValueError:record('Маршрут VPN '+p.stem,None,'Не удалось прочитать адресацию')
  stem=p.stem
  if not re.fullmatch(r'[A-Za-z0-9_.-]+',stem):
   record('Служба OpenVPN',None,'Нестандартное имя конфигурации');continue
  units=['openvpn-server@'+stem] if p.parent.name=='server' else ['openvpn@'+stem]
  code,out=command(['systemctl','is-active',units[0]])
  record('Служба '+units[0],None if code is None else code==0,out.strip() or 'Состояние недоступно')
  port=values.get('port','1194');proto=values.get('proto','udp')
  if not port.isdigit() or not 1<=int(port)<=65535:
   record('Порт '+stem,None,'Порт не удалось определить');continue
  code,out=command(['ss','-H','-ln'+('t' if proto.startswith('tcp') else 'u')])
  listening=any(len(f:=line.split())>=5 and f[-2].endswith(':'+port) for line in out.splitlines())
  record('Порт '+stem,None if code!=0 else listening,proto+' '+port)
code,out=command(['ip','-j','-d','link','show'])
try:links=json.loads(out) if code==0 else None
except ValueError:links=None
matched=[] if links is None else [x for x in links if x.get('linkinfo',{}).get('info_kind')=='gre' and x.get('linkinfo',{}).get('info_data',{}).get('remote')==peer]
record('GRE к выбранному серверу',None if links is None else bool(matched),'Интерфейсов к выбранному партнёру: '+str(len(matched)))
for link in matched:
 name=link['ifname'];record('Интерфейс '+name,'UP' in link.get('flags',[]),'Административное состояние GRE')
 code,out=command(['ip','-j','-4','addr','show','dev',name])
 try:addresses=json.loads(out) if code==0 else []
 except ValueError:addresses=[]
 candidates=[]
 for interface in addresses:
  for addr in interface.get('addr_info',[]):
   if addr.get('family')=='inet' and addr.get('prefixlen')==30:
    net=ipaddress.ip_network(addr['local']+'/30',strict=False)
    candidates.extend(str(ip) for ip in net.hosts() if str(ip)!=addr['local'])
 if len(candidates)==1:
  code,out=command(['ping','-n','-c','1','-W','2','-I',name,candidates[0]])
  record('Ответ GRE-партнёра',True if code==0 else None,'ICMP через '+name+'; отсутствие ответа само по себе не доказывает отказ VPN')
 else:record('Ответ GRE-партнёра',None,'Адрес GRE-партнёра нельзя однозначно определить')
code,out=command(['swanctl','--list-sas'])
if code==0:
 blocks=re.findall(r'^\S[^\n]*(?:\n[ \t]+[^\n]*)*',out,re.M)
 active=any(re.search(r'(?<![0-9.])'+re.escape(peer)+r'(?![0-9.])',b) and 'INSTALLED' in b for b in blocks)
 record('IPsec к выбранному серверу',active,'Установленная IPsec SA к выбранному партнёру' if active else 'Установленная SA к выбранному партнёру не найдена')
else:record('IPsec к выбранному серверу',None,'swanctl недоступен; возможен другой IPsec backend')
print(json.dumps(checks,ensure_ascii=False))
'''

def inspect_servers(config,endpoints,inventory,verify=False):
    checks=[];warnings=[]
    for ep in endpoints:
        inv=inventory[ep.role]
        checks.append({'server':ep.role,'check':'SSH, ОС и инвентаризация','passed':True,'detail':inv['os'].get('PRETTY_NAME',inv['os'].get('ID',''))})
        if not inv.get('managed'):
            warnings.append(ep.role+': служебные файлы установщика не найдены; это не означает отсутствия VPN.')
        if verify:
            try:runtime=json.loads(ep.python(RUNTIME,{'role':ep.role,'peer':config['nl_ip' if ep.role=='ru' else 'ru_ip']}))
            except Exception:runtime=[]
            if not isinstance(runtime,list) or not runtime:runtime=[{'check':'Состояние VPN','passed':None,'detail':'Не получен результат диагностики'}]
            for item in runtime:
                item['server']=ep.role;checks.append(item)
    return {'checks':checks,'warnings':warnings,'complete':all(c['passed'] is not None for c in checks),'healthy':all(c['passed'] is True for c in checks),'limitations':['Проверка не создаёт файлы, интерфейсы и сетевые пространства и не перезапускает службы.','Сквозное подключение клиента, HTTPS и фактические выходы пользовательского трафика не проверялись.']}
