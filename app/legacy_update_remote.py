"""Bounded authentication update for an identified installation without installer state."""
import ast,base64,datetime,hashlib,hmac,ipaddress,json,os,pathlib,re,secrets,shlex,subprocess
CONF=['/etc/openvpn/server/ru.conf','/etc/openvpn/server/ru-tcp.conf']
USERS='/etc/openvpn/server/users.json'
UTILITY='/usr/local/sbin/ovpn-user'
NETWORK='/usr/local/sbin/ovpn-network'
AUTH='/etc/openvpn/server/auth.py'
LISTS=['/etc/ovpn-routing/force-ru.txt','/etc/ovpn-routing/extra-nl.txt']
EXTRA=['/etc/ovpn-routing/dns.json','/usr/local/sbin/ovpn-dns-policy','/etc/systemd/system/ovpn-dns.service','/etc/systemd/system/openvpn-server@ru.service.d/50-vpnai-dns.conf','/etc/systemd/system/openvpn-server@ru-tcp.service.d/50-vpnai-dns.conf']
PROFILE_DIR='/root/ovpn-profiles'
BACKUPS='/root/ovpn-auth-backups'

def command(args,check=True):
 r=subprocess.run(args,capture_output=True,text=True,timeout=30)
 if check and r.returncode:raise ValueError('Не выполнена команда: '+args[0])
 return r

def read(path):
 p=pathlib.Path(path)
 if p.is_symlink():raise ValueError('Ссылки вместо файлов конфигурации не поддерживаются.')
 return p.read_bytes() if p.is_file() else None

def rows(text):
 result=[];block=None
 for line in text.splitlines():
  stripped=line.strip()
  if block:
   if stripped=='</'+block+'>':block=None
   continue
  if re.fullmatch(r'<[A-Za-z0-9_-]+>',stripped):block=stripped[1:-1];continue
  fields=shlex.split(line,comments=True)
  if fields:result.append(fields)
 return result

def one(items,name):
 found=[r for r in items if r[0]==name]
 if len(found)!=1:raise ValueError('Неоднозначный параметр OpenVPN: '+name)
 return found[0]

def template(source):
 tree=ast.parse(source);found=[]
 for f in tree.body:
  if isinstance(f,ast.FunctionDef) and f.name=='create_profiles':
   found += [n.value for n in ast.walk(f) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='profile' for t in n.targets) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str)]
 if len(found)!=1:raise ValueError('Не распознан генератор профилей. Пользователи не изменены.')
 return tree,found[0]

def snapshot(data):
 files={p:read(p) for p in CONF+[USERS,UTILITY,NETWORK,AUTH]+LISTS+EXTRA}
 if any(files[p] is None for p in CONF+[USERS,UTILITY,NETWORK,AUTH]):raise ValueError('Не найдены совместимые конфигурации и инструменты установленного VPN.')
 users=json.loads(files[USERS]);public=[]
 if not isinstance(users,dict):raise ValueError('Не распознана база пользователей.')
 for name,record in sorted(users.items()):
  if not re.fullmatch(r'[A-Za-z0-9_-]{1,48}',name) or not isinstance(record,dict):raise ValueError('Не распознана база пользователей.')
  if record.get('deleted'):continue
  public.append({'name':name,'enabled':bool(record.get('enabled'))})
  for suffix in ('.ovpn','-UDP.ovpn','-TCP.ovpn','-credentials.txt'):
   path=str(pathlib.Path(PROFILE_DIR)/(name+suffix));files[path]=read(path)

 settings=[]
 for p in CONF:
  f=rows(files[p].decode())
  if any(r[0] in ('config','include','client-cert-not-required') or r[0]=='verify-client-cert' and r[1:]!=['require'] for r in f):raise ValueError('Нестандартная конфигурация требует отдельной проверки.')
  server=one(f,'server');port=one(f,'port');dev=one(f,'dev')
  net=ipaddress.ip_network('/'.join(server[1:]),strict=False)
  if net.version!=4 or not net.is_private or len(port)!=2 or not port[1].isdigit():raise ValueError('Не распознаны параметры OpenVPN.')
  auth=[r for r in f if r[0]=='auth-user-pass-verify']
  if len(auth)>1 or auth and auth[0][1:]!=[AUTH,'via-file']:raise ValueError('Нестандартный обработчик входа требует отдельной проверки.')
  settings.append({'net':str(net),'port':int(port[1]),'password':bool(auth),'split':any(r[0]=='client-connect' and r[1:]==['/usr/local/libexec/ovpn-split-connect'] for r in f),'redirect':any(r[0]=='push' and len(r)>1 and r[1].startswith('redirect-gateway ') for r in f)})
 if settings[0]['port']!=settings[1]['port'] or settings[0]['password']!=settings[1]['password']:raise ValueError('Параметры UDP и TCP различаются. Автоматическое переключение не выполнено.')
 network=files[NETWORK].decode()
 if all(s['split'] and not s['redirect'] for s in settings):routing='split'
 elif all(s['redirect'] and not s['split'] for s in settings) and '--match-set ovpn_nl' in network:routing='full_mixed'
 elif all(s['redirect'] and not s['split'] for s in settings) and '-j MARK --set-xmark 0x310/0xfff' in network:routing='full_nl'
 else:raise ValueError('Не удалось однозначно прочитать текущую маршрутизацию.')
 links=json.loads(command(['ip','-j','-d','link','show','gre-nl']).stdout)
 if len(links)!=1:raise ValueError('Не распознан GRE-туннель.')
 gre=links[0].get('linkinfo',{})
 if gre.get('info_kind')!='gre' or gre.get('info_data',{}).get('remote')!=data['nl_ip'] or gre.get('info_data',{}).get('local')!=data['ru_ip']:raise ValueError('Установка относится к другой паре серверов.')
 tree,node=template(files[UTILITY].decode());remote=one(rows(node.value),'remote')
 if remote[1:]!=[data['ru_ip'],str(settings[0]['port'])]:raise ValueError('Профили относятся к другому адресу или порту.')
 config={'ru_ip':data['ru_ip'],'nl_ip':data['nl_ip'],'vpn_net':settings[0]['net'],'tcp_net':settings[1]['net'],'ovpn_port':settings[0]['port'],'routing_mode':routing,'auth_mode':'password' if settings[0]['password'] else 'certificate'}
 manual=[]
 for path in LISTS:
  addresses=[]
  for line in (files[path] or b'').decode().splitlines():
   line=line.split('#',1)[0].strip()
   if line:addresses.append(str(ipaddress.ip_network(line,strict=False)))
  manual.append(sorted(set(addresses)))
 fingerprint={p:hashlib.sha256(v).hexdigest() if v is not None else None for p,v in files.items()}
 revision=hashlib.sha256(json.dumps({'files':fingerprint,'config':config},sort_keys=True).encode()).hexdigest()
 result={'config':config,'users':public,'user_count':len(public),'active_user_count':sum(x['enabled'] for x in public),'ru_routes':manual[0],'eu_routes':manual[1],'state':False,'legacy':True,'revision':revision,'capabilities':{'auth':True,'dns':True,'routing':False,'port':False,'routes':False}}
 return result,files,users

def rewrite(text,mode,server=False):
 directive='auth-user-pass-verify' if server else 'auth-user-pass';out=[];block=None
 for line in text.splitlines(keepends=True):
  stripped=line.strip()
  if block:
   out.append(line)
   if stripped=='</'+block+'>':block=None
   continue
  if re.fullmatch(r'<[A-Za-z0-9_-]+>',stripped):block=stripped[1:-1];out.append(line);continue
  f=shlex.split(line,comments=True)
  if not f or f[0]!=directive:out.append(line)
 text=''.join(out)
 if mode=='password':text=text.rstrip('\r\n')+'\n'+(directive+' '+AUTH+' via-file' if server else directive)+'\n'
 return text

def utility(source,mode):
 tree,node=template(source);segment=ast.get_source_segment(source,node);replacement=repr(rewrite(node.value,mode))
 if source.count(segment)!=1:raise ValueError('Неоднозначный шаблон профиля.')
 changed=source.replace(segment,replacement,1);node.value=ast.literal_eval(replacement)
 if ast.dump(tree)!=ast.dump(ast.parse(changed)):raise ValueError('Не удалось безопасно обновить шаблон профилей.')
 return changed

def atomic(path,body,mode):
 p=pathlib.Path(path);tmp=p.with_name(p.name+'.auth-new')
 try:tmp.write_bytes(body);tmp.chmod(mode);tmp.replace(p)
 finally:tmp.unlink(missing_ok=True)

def apply(data):
 import fcntl
 with open('/run/ovpn-user.lock','a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  current,files,users=snapshot(data)
  if current['revision']!=data.get('revision'):raise ValueError('Настройки изменились. Считайте их заново перед применением.')
  if data.get('confirmed') is not True:raise ValueError('Не подтверждено переключение входа.')
  mode=data.get('auth')
  if mode not in ('password','certificate'):raise ValueError('Неизвестный способ входа.')
  if current['config']['auth_mode']==mode:return dict(current,unchanged=True,reconnect_required=False)
  changes={p:rewrite(files[p].decode(),mode,True).encode() for p in CONF}
  changes[UTILITY]=utility(files[UTILITY].decode(),mode).encode()
  for user in current['users']:
   name=user['name']
   if mode=='password' and user['enabled']:
    record=users[name];p=str(pathlib.Path(PROFILE_DIR)/(name+'-credentials.txt'));text=(files[p] or b'').decode()
    password=next((line[10:] for line in text.splitlines() if line.startswith('Password: ')),None)
    try:valid=password is not None and hmac.compare_digest(hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(record['salt']),300000).hex(),record['hash'])
    except (KeyError,ValueError):valid=False
    if not valid:raise ValueError('У пользователя '+name+' нет проверенного сохранённого пароля. Задайте его в управлении и повторите операцию.')
   for suffix in ('.ovpn','-UDP.ovpn','-TCP.ovpn'):
    path=str(pathlib.Path(PROFILE_DIR)/(name+suffix));body=files[path]
    if body is None:
     if user['enabled'] and suffix in ('-UDP.ovpn','-TCP.ovpn'):raise ValueError('Нет готового профиля пользователя '+name+'. Автоматическое создание файлов не выполняется.')
     continue
    text=body.decode()
    if not all('<'+tag+'>' in text and '</'+tag+'>' in text for tag in ('ca','cert','key','tls-crypt')) or one(rows(text),'remote')[1:]!=[data['ru_ip'],str(current['config']['ovpn_port'])]:raise ValueError('Не распознан профиль пользователя '+name)
    changes[path]=rewrite(text,mode).encode()
  active=[u for u in ('openvpn-server@ru.service','openvpn-server@ru-tcp.service') if command(['systemctl','is-active','--quiet',u],False).returncode==0]
  if not active:raise ValueError('Нет активной службы OpenVPN. Сначала проверьте состояние VPN.')
  backup=pathlib.Path(BACKUPS)/(datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4));backup.mkdir(parents=True,mode=0o700);backup.parent.chmod(0o700)
  receipt={p:{'body':base64.b64encode(files[p]).decode() if files[p] is not None else None,'mode':pathlib.Path(p).stat().st_mode&0o777 if files[p] is not None else 0o600} for p in changes}
  atomic(str(backup/'files.json'),json.dumps(receipt).encode(),0o600)
  try:
   command(['systemctl','stop']+active)
   for p,body in changes.items():atomic(p,body,receipt[p]['mode'])
   command(['systemctl','restart']+active)
   for u in active:command(['systemctl','is-active','--quiet',u])
   result,after,_=snapshot(data)
   if result['config']['auth_mode']!=mode or any(after[p]!=before for p,before in files.items() if p not in changes):raise ValueError('Итоговая проверка сохранности настроек не пройдена.')
  except Exception as error:
   ok=True
   for p,item in receipt.items():
    try:
     if item['body'] is None:pathlib.Path(p).unlink(missing_ok=True)
     else:atomic(p,base64.b64decode(item['body']),item['mode'])
    except Exception:ok=False
   try:command(['systemctl','restart']+active)
   except Exception:ok=False
   raise ValueError(('Прежние настройки восстановлены.' if ok else 'Откат не завершён, проверьте сервер.')+' Причина: '+str(error)[:300]+' Резервная копия: '+str(backup)) from None
  return dict(result,backup=str(backup),reconnect_required=True)

def execute(data):
 if data['operation']=='read':return snapshot(data)[0]
 if data['operation']=='apply':return apply(data)
 raise ValueError('Неизвестная операция.')
