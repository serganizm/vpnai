"""Pinned-SSH DNS transaction; only execute() performs remote operations."""
import base64,datetime,hashlib,ipaddress,json,os,pathlib,re,secrets,shlex,socket,struct,subprocess,time
CONF=['/etc/openvpn/server/ru.conf','/etc/openvpn/server/ru-tcp.conf']
DROPINS=['/etc/systemd/system/openvpn-server@ru.service.d/50-vpnai-dns.conf','/etc/systemd/system/openvpn-server@ru-tcp.service.d/50-vpnai-dns.conf']
STATE='/etc/ovpn-routing/dns.json'
HELPER='/usr/local/sbin/ovpn-dns-policy'
UNIT='/etc/systemd/system/ovpn-dns.service'
OWNER='/var/lib/ovpn-installer/owned.json'
BEGIN='# VPNAI DNS BEGIN'
END='# VPNAI DNS END'

def read(path):
 p=pathlib.Path(path)
 if p.is_symlink():raise ValueError('Символическая ссылка в настройках DNS не поддерживается.')
 return p.read_bytes() if p.exists() else None

def snapshot():
 return {p:read(p) for p in CONF+[STATE,HELPER,UNIT,OWNER]+DROPINS}

def revision(files):return hashlib.sha256(json.dumps({p:hashlib.sha256(b).hexdigest() if b is not None else None for p,b in files.items()},sort_keys=True).encode()).hexdigest()

def directives(text):
 servers=[]
 for line in text.splitlines():
  f=shlex.split(line,comments=True)
  if len(f)==2 and f[0]=='push':
   option=f[1].split()
   if len(option)==3 and option[:2]==['dhcp-option','DNS']:servers.append(str(ipaddress.IPv4Address(option[2])))
 return servers

def status():
 files=snapshot();profiles=[]
 for path in CONF:
  body=files[path]
  profiles.append({'name':pathlib.Path(path).stem,'exists':body is not None,'servers':directives(body.decode()) if body else []})
 saved=json.loads(files[STATE]) if files[STATE] else None
 servers=profiles[0]['servers'];same=all(p['exists'] and p['servers']==servers for p in profiles)
 provider='google' if servers==['8.8.8.8','8.8.4.4'] else 'cloudflare' if servers==['1.1.1.1','1.0.0.1'] else 'custom' if servers else 'unchanged'
 ready=False
 if saved and saved.get('version')==1:
  try:
   ready=set(inspect(saved))==rules(saved)
   if saved.get('servers'):
    table=json.loads(command(['ip','-j','route','show','table',str(TABLE)],False).stdout or '[]')
    ready=ready and any(x.get('dev')==saved['interface'] and x.get('gateway')==saved['gateway'] and x.get('dst')=='default' for x in table) and any(x.get('type')=='unreachable' and x.get('dst')=='default' for x in table)
  except (ValueError,KeyError):pass
 incomplete=False
 if not saved:
  incomplete=any(x.get('priority')==PRIORITY for x in json.loads(command(['ip','-j','rule','show']).stdout))
 return {'incomplete':incomplete,'policy_ready':ready,'provider':provider,'servers':servers,'consistent':same,'profiles':profiles,'managed':bool(saved and saved.get('version')==1),'revision':revision(files),'route':'eu' if servers and ready and saved and saved.get('servers')==servers and same else 'unknown','configured':bool(servers)}

def command(args,check=True):
 r=subprocess.run(args,capture_output=True,text=True,timeout=30)
 if check and r.returncode:raise ValueError('Команда DNS не выполнена: '+args[0])
 return r

def query(server,tcp=False):
 ident=secrets.randbelow(65536);q=struct.pack('!HHHHHH',ident,0x100,1,0,0,0)+b'\x07example\x03com\x00'+struct.pack('!HH',1,1)
 with socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
  s.settimeout(3);s.connect((server,53))
  if tcp:
   s.sendall(struct.pack('!H',len(q))+q)
   def receive(n):
    b=b''
    while len(b)<n:
     v=s.recv(n-len(b))
     if not v:raise ValueError('Неполный ответ DNS.')
     b+=v
    return b
   length=struct.unpack('!H',receive(2))[0]
   if not 12<=length<=4096:raise ValueError('Некорректный ответ DNS.')
   answer=receive(length)
  else:s.send(q);answer=s.recv(4096)
 if len(answer)<12 or struct.unpack('!H',answer[:2])[0]!=ident or not answer[2]&0x80 or answer[3]&0xf not in (0,3):raise ValueError('DNS не ответил корректно.')

def probe(servers):
 rows=[]
 for server in servers:
  row={'server':server}
  for name,tcp in [('udp',False),('tcp',True)]:
   try:query(server,tcp);row[name]=True
   except (OSError,ValueError):row[name]=False
  rows.append(row)
 return {'checks':rows,'passed':all(r['udp'] and r['tcp'] for r in rows)}

def rewrite(text,servers):
 if text.count(BEGIN)!=text.count(END) or text.count(BEGIN)>1:raise ValueError('Повреждён блок DNS в конфигурации.')
 clean=re.sub(r'(?m)^'+re.escape(BEGIN)+r'\n.*?^'+re.escape(END)+r'\n?', '',text,flags=re.S)
 lines=[]
 for line in clean.splitlines():
  f=shlex.split(line,comments=True)
  if len(f)==2 and f[0]=='push' and f[1].split()[:2]==['dhcp-option','DNS']:continue
  lines.append(line)
 if servers:
  lines += [BEGIN]+['push "dhcp-option DNS '+ip+'"' for ip in servers]+['push "route '+ip+' 255.255.255.255"' for ip in servers]+[END]
 return '\n'.join(lines)+'\n'

def atomic(path,body,mode=0o600):
 p=pathlib.Path(path);p.parent.mkdir(parents=True,exist_ok=True);tmp=p.with_name(p.name+'.dns-new')
 try:tmp.write_bytes(body);tmp.chmod(mode);tmp.replace(p)
 finally:tmp.unlink(missing_ok=True)

def recover_orphan(files,networks,peer,route):
 # Recover only this app's complete, recognizable rules after an exact file rollback.
 if any(files[p] is not None for p in [STATE,HELPER,UNIT]+DROPINS):return None
 proof=False
 for receipt in sorted(pathlib.Path('/root/ovpn-dns-backups').glob('*/files.json'))[-32:]:
  try:
   previous=json.loads(read(str(receipt)))
   if set(previous)!=set(files):continue
   if all((base64.b64decode(previous[p]['body']) if previous[p]['body'] is not None else None)==body for p,body in files.items()):proof=True;break
  except (ValueError,KeyError,TypeError):continue
 if not proof:return None
 current=json.loads(command(['ip','-j','rule','show']).stdout)
 selected=[x for x in current if x.get('priority')==PRIORITY]
 try:keys=[rule_key(x) for x in selected]
 except (ValueError,TypeError):return None
 servers=sorted({str(ipaddress.ip_network(x[1]).network_address) for x in keys})
 if not 1<=len(servers)<=2 or not all(ipaddress.ip_address(ip).is_global for ip in servers):return None
 candidate={'version':1,'provider':'custom','servers':servers,'peer':peer,'networks':networks,'interface':route['dev'],'gateway':route['gateway']}
 if len(keys)!=len(set(keys)) or set(keys)!=rules(candidate):return None
 table=json.loads(command(['ip','-j','route','show','table',str(TABLE)],False).stdout or '[]')
 if len(table)!=2 or not any(x.get('dst')=='default' and x.get('dev')==route['dev'] and x.get('gateway')==route['gateway'] for x in table) or not any(x.get('dst')=='default' and x.get('type')=='unreachable' for x in table):return None
 inspect(candidate)
 return candidate

def configure(data):
 files=snapshot()
 if revision(files)!=data['revision']:raise ValueError('Настройки изменились. Считайте их заново перед применением.')
 old=json.loads(files[STATE]) if files[STATE] else None
 factory={HELPER:data['helper'].encode(),UNIT:data['unit'].encode(),**{p:b'[Unit]\nRequires=ovpn-dns.service\nAfter=ovpn-dns.service\n' for p in DROPINS}}
 if old is None and any(files[p] is not None and files[p]!=factory[p] for p in factory):raise ValueError('Найдены сторонние или незавершённые DNS-компоненты. Проверьте их перед применением.')
 if old and (old.get('version')!=1 or old.get('peer')!=data['peer']):raise ValueError('DNS-настройки относятся к другой паре серверов.')
 if files[OWNER] is not None and not isinstance(json.loads(files[OWNER]),dict):raise ValueError('Некорректный список компонентов установщика.')
 networks=[]
 for path in CONF:
  if files[path] is None:raise ValueError('Не найдены обе конфигурации OpenVPN RU.')
  text=files[path].decode();rows=[shlex.split(line,comments=True) for line in text.splitlines()]
  if any(row and row[0] in ('config','include') for row in rows):raise ValueError('Внешние включения конфигураций требуют ручной проверки DNS.')
  addresses=[row for row in rows if row and row[0]=='server']
  if len(addresses)!=1 or len(addresses[0])!=3:raise ValueError('Не удалось определить подсеть OpenVPN.')
  net=ipaddress.ip_network('/'.join(addresses[0][1:]),strict=False)
  if net.version!=4 or not net.is_private:raise ValueError('Неожиданная VPN-подсеть.')
  networks.append(str(net))
  # Only this project's known services are restarted.
  if not any(row and row[0]=='dev' for row in rows):raise ValueError('Некорректная конфигурация OpenVPN.')
 routes=json.loads(command(['ip','-j','route','show','table','310'],False).stdout or '[]')
 links=json.loads(command(['ip','-j','-d','link','show']).stdout)
 defaults=[r for r in routes if r.get('dst')=='default' and r.get('dev') and r.get('gateway')]
 matching=[r for r in defaults if any(l.get('ifname')==r['dev'] and 'UP' in l.get('flags',[]) and l.get('linkinfo',{}).get('info_kind')=='gre' and l.get('linkinfo',{}).get('info_data',{}).get('remote')==data['peer'] for l in links)]
 if data['servers'] and len(matching)!=1:raise ValueError('Не найден однозначный маршрут GRE к выбранному EU-серверу в таблице 310.')
 if data['servers']:
  sas=command(['swanctl','--list-sas'],False)
  block=re.search(r'^ovpn-gre:[^\n]*(?:\n[ \t]+[^\n]*)*',sas.stdout,re.M)
  if sas.returncode or not block or not re.search(r'^\s+gre:\s+#[^\n]*\bINSTALLED\b',block.group(),re.M) or not re.search(r'(?<![0-9.])'+re.escape(data['peer'])+r'(?![0-9.])',block.group()):raise ValueError('GRE/IPsec к выбранному EU не подтверждён. Сначала проверьте туннель; DNS не изменён.')
  if command(['iptables','-C','OUTPUT','-d',data['peer'],'-p','gre','-m','policy','--dir','out','--pol','none','-j','DROP'],False).returncode:raise ValueError('Не подтверждена защита GRE от незашифрованного выхода. DNS не изменён.')

 route=matching[0] if matching else {'dev':old['interface'],'gateway':old['gateway']} if old else {'dev':'gre-nl','gateway':'10.78.0.2'}
 config={'version':1,'provider':data['provider'],'servers':data['servers'],'peer':data['peer'],'networks':networks,'interface':route['dev'],'gateway':route['gateway'],'previous_rules':[list(x) for x in rules(old)] if old else []}
 # Functions from the policy module are injected, never read from a server executable.
 if old is None:
  existing_rules=json.loads(command(['ip','-j','rule','show']).stdout)
  occupied=json.loads(command(['ip','-j','route','show','table',str(TABLE)],False).stdout or '[]')
  if occupied or any(x.get('priority')==PRIORITY for x in existing_rules):
   old=recover_orphan(files,networks,data['peer'],route)
   if old is None:raise ValueError('Ресурсы маршрутизации DNS уже используются. Сервер не изменён.')
   config['previous_rules']=[list(x) for x in rules(old)]
 inspect(config)
 active_units=[unit for unit in ['openvpn-server@ru.service','openvpn-server@ru-tcp.service'] if command(['systemctl','is-active','--quiet',unit],False).returncode==0]
 if not active_units:raise ValueError('Нет активной службы OpenVPN. Сначала проверьте VPN.')
 backup=pathlib.Path('/root/ovpn-dns-backups')/(datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4))
 backup.mkdir(parents=True,mode=0o700);backup.parent.chmod(0o700)
 receipt={p:{'body':base64.b64encode(body).decode() if body is not None else None,'mode':pathlib.Path(p).stat().st_mode&0o777 if body is not None else None} for p,body in files.items()}
 atomic(str(backup/'files.json'),json.dumps(receipt).encode())
 enabled=command(['systemctl','is-enabled','ovpn-dns.service'],False).returncode==0
 active=command(['systemctl','is-active','ovpn-dns.service'],False).returncode==0
 try:
  command(['systemctl','stop']+active_units)
  for path in CONF:atomic(path,rewrite(files[path].decode(),data['servers']).encode())
  atomic(STATE,json.dumps(config,indent=2).encode());atomic(HELPER,data['helper'].encode(),0o700);atomic(UNIT,data['unit'].encode(),0o644)
  for path in DROPINS:atomic(path,b'[Unit]\nRequires=ovpn-dns.service\nAfter=ovpn-dns.service\n',0o644)
  command(['systemctl','daemon-reload'])
  apply(config)
  if data['servers']:command(['systemctl','enable','ovpn-dns.service'])
  else:command(['systemctl','disable','ovpn-dns.service'])
  # A oneshot is started so its stop action also cleans up during uninstall.
  command(['systemctl','restart','ovpn-dns.service'])
  command(['systemctl','restart']+active_units)
  for unit in active_units:command(['systemctl','is-active','--quiet',unit])
  verified=status()
  if not verified['consistent'] or verified['servers']!=data['servers'] or data['servers'] and not verified['policy_ready']:raise ValueError('Итоговая проверка DNS не пройдена.')
  if files[OWNER] is not None:
   owned=json.loads(files[OWNER])
   for path in [STATE,HELPER,UNIT]+DROPINS:owned.setdefault(path,{'backup':None})
   atomic(OWNER,json.dumps(owned).encode())
 except Exception as error:
  rollback_ok=True
  try:
   command(['systemctl','stop','ovpn-dns.service'],False)
   apply(config,clear=True)
  except Exception:rollback_ok=False
  for path,info in receipt.items():
   try:
    if info['body'] is None:pathlib.Path(path).unlink(missing_ok=True)
    else:atomic(path,base64.b64decode(info['body']),info['mode'])
   except Exception:rollback_ok=False
  try:
   command(['systemctl','daemon-reload'])
   if old:apply(old)
   command(['systemctl','enable' if enabled else 'disable','ovpn-dns.service'],False)
   if active and old:command(['systemctl','restart','ovpn-dns.service'])
   command(['systemctl','restart']+active_units)
  except Exception:rollback_ok=False
  raise ValueError(('Ошибка применения; прежние настройки восстановлены.' if rollback_ok else 'Ошибка применения; откат неполный, проверьте сервер.')+' Причина: '+str(error)[:500]+' Резервная копия: '+str(backup)) from None
 return dict(status(),backup=str(backup),reconnect_required=True)

def execute(data):
 if data['operation']=='read':return status()
 if data['operation']=='probe':return probe(data['servers'])
 if data['operation']=='apply':return configure(data)
 raise ValueError('Неизвестная операция DNS.')
