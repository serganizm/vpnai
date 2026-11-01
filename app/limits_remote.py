"""Explicit, backed-up deployment of session limits to an existing VPNAI server."""
import base64,contextlib,hashlib,json,pathlib,re,secrets,shlex,subprocess,time
CONF=[pathlib.Path('/etc/openvpn/server/ru.conf'),pathlib.Path('/etc/openvpn/server/ru-tcp.conf')]
POLICY=pathlib.Path('/etc/openvpn/server/connection-limits.json')
HELPER=pathlib.Path('/usr/local/libexec/ovpn-session-limit')
HOOK='/usr/local/libexec/ovpn-split-connect'
BACKUPS=pathlib.Path('/root/ovpn-limits-backups')
CERTS=pathlib.Path('/etc/openvpn/server/pki/issued')
def certificate(name):
 try:return hashlib.sha256((CERTS/(name+'.crt')).read_bytes()).hexdigest()
 except OSError:return None
def validate(value,inherit=False):
 if inherit and value is None:return None
 if type(value) is not int or not 0<=value<=1000:raise ValueError('Лимит: целое число от 0 до 1000.')
 return value
def read():
 p=json.loads(POLICY.read_text()) if POLICY.exists() else {'version':1,'default':0,'users':{}}
 validate(p['default'])
 if p.get('version')!=1 or not isinstance(p.get('users'),dict):raise ValueError('Повреждён файл лимитов.')
 for name,value in p['users'].items():
  if not re.fullmatch(r'[A-Za-z0-9_-]{1,48}',name):raise ValueError('Некорректный пользователь в лимитах.')
  validate(value)
 users_path=POLICY.with_name('users.json');users_body=users_path.read_bytes() if users_path.exists() else b'{}';users=json.loads(users_body)
 if not isinstance(users,dict):raise ValueError('Повреждён список пользователей.')
 certificates={name:certificate(name) for name in users if re.fullmatch(r'[A-Za-z0-9_-]{1,48}',name)}
 bodies=[f.read_text() for f in CONF]
 def configured(body):
  rows=[shlex.split(line,comments=True) for line in body.splitlines()]
  connect=[row for row in rows if row and row[0]=='client-connect'];disconnect=[row for row in rows if row and row[0]=='client-disconnect']
  return len(connect)==len(disconnect)==1 and len(connect[0])==len(disconnect[0])==2 and shlex.split(connect[0][1]) in (['/usr/local/libexec/ovpn-session-limit','connect'],['/usr/local/libexec/ovpn-session-limit','connect-full']) and shlex.split(disconnect[0][1])==['/usr/local/libexec/ovpn-session-limit','disconnect']
 installed=HELPER.exists() and all(configured(b) for b in bodies)
 revision=hashlib.sha256(json.dumps({'policy':p,'configs':bodies,'users':hashlib.sha256(users_body).hexdigest(),'certificates':certificates,'helper':hashlib.sha256(HELPER.read_bytes()).hexdigest() if HELPER.exists() else None},sort_keys=True).encode()).hexdigest()
 p=dict(p);p['users']={n:v for n,v in p['users'].items() if p.get('identities',{}).get(n)==certificate(n) and certificate(n) is not None}
 return dict(p,installed=installed,revision=revision)
def command(args):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=45)
def execute(data):
 current=read()
 if data['operation']=='read':return current
 if not data.get('confirmed'):raise ValueError('Подтвердите применение лимитов.')
 if not secrets.compare_digest(str(data.get('revision','')),current['revision']):raise ValueError('Лимиты изменились. Считайте актуальные настройки.')
 if not current['installed'] and data.get('restart_confirmed') is not True:raise ValueError('Первое включение требует перезапуска OpenVPN. Подтвердите переподключение устройств.')
 import fcntl
 with open('/run/ovpn-user.lock','a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  # Recheck after obtaining the users lock.
  if read()['revision']!=current['revision']:raise ValueError('Настройки изменились; повторите чтение.')
  p={k:current[k] for k in ('version','default','users')};p['users']=dict(p['users']);p['identities']=dict(current.get('identities',{}))
  if data['operation']=='default':p['default']=validate(data['value'])
  elif data['operation']=='user':
   import re
   name=data.get('name','');users=json.loads(POLICY.with_name('users.json').read_text())
   if not re.fullmatch(r'[A-Za-z0-9_-]{1,48}',name) or name not in users or users[name].get('deleted'):raise ValueError('Пользователь не найден.')
   value=validate(data.get('value'),True)
   if value is None:p['users'].pop(name,None);p['identities'].pop(name,None)
   else:
    serial=certificate(name)
    if serial is None:raise ValueError('Сертификат пользователя не найден.')
    p['users'][name]=value;p['identities'][name]=serial
  else:raise ValueError('Неизвестная операция лимитов.')
  bodies={f:f.read_bytes() for f in CONF}
  if not current['installed']:
   for body in bodies.values():
    lines=[shlex.split(line.split('#')[0]) for line in body.decode().splitlines() if line.strip() and not line.lstrip().startswith('#')]
    hooks=[x for x in lines if x and x[0] in ('client-connect','client-disconnect')]
    if hooks!=[['client-connect',HOOK]] and not (not hooks and any(x[0]=='push' and len(x)>1 and x[1].startswith('redirect-gateway ') for x in lines)):raise ValueError('Неизвестные обработчики OpenVPN. Автоматическая замена запрещена.')
  paths=[*CONF,POLICY,HELPER];before={str(f):{'body':base64.b64encode(f.read_bytes()).decode(),'mode':f.stat().st_mode&0o777} if f.exists() else None for f in paths}
  BACKUPS.mkdir(mode=0o700,parents=True,exist_ok=True);BACKUPS.chmod(0o700);backup=BACKUPS/(str(time.time_ns())+'-'+secrets.token_hex(4));backup.mkdir(mode=0o700)
  receipt=backup/'files.json';receipt.write_text(json.dumps(before));receipt.chmod(0o600)
  active=[]
  if not current['installed']:
   for unit in ['openvpn-server@ru.service','openvpn-server@ru-tcp.service']:
    if subprocess.run(['systemctl','is-active','--quiet',unit],capture_output=True).returncode==0:active.append(unit)
  def write(f,body,mode=0o600):
   tmp=f.with_name(f.name+'.vpnai-'+secrets.token_hex(6));f.parent.mkdir(parents=True,exist_ok=True)
   try:tmp.write_bytes(body);tmp.chmod(mode);tmp.replace(f)
   finally:
    with contextlib.suppress(FileNotFoundError):tmp.unlink()
  services_touched=False
  try:
   if not current['installed']:
    source=data['helper'];compile(source,'ovpn-session-limit','exec');write(HELPER,('#!/usr/bin/python3\n'+source).encode(),0o700)
    prepared={}
    for f,body in bodies.items():
     lines=body.decode().splitlines();lines=[line for line in lines if not line.lstrip().startswith('client-connect ')];mode='connect-full' if any(line.startswith('push ') and 'redirect-gateway' in line for line in lines) else 'connect'
     lines+=['client-connect '+json.dumps('/usr/local/libexec/ovpn-session-limit '+mode),'client-disconnect '+json.dumps('/usr/local/libexec/ovpn-session-limit disconnect')]
     prepared[f]=('\n'.join(lines)+'\n').encode();candidate=backup/(f.name+'.check');write(candidate,prepared[f])
     command(['openvpn','--config',str(candidate),'--show-ciphers'])
    for f,body in prepared.items():write(f,body,before[str(f)]['mode'])
   write(POLICY,json.dumps(p,ensure_ascii=False,indent=2).encode())
   for unit in active:
    services_touched=True;command(['systemctl','restart',unit]);command(['systemctl','is-active','--quiet',unit])
  except BaseException as original:
   errors=[]
   for f in paths:
    try:
     old=before[str(f)]
     if old is None:
      if f.exists():f.unlink()
     else:write(f,base64.b64decode(old['body']),old['mode'])
    except Exception:errors.append(str(f))
   for unit in active if services_touched else []:
    try:command(['systemctl','restart',unit])
    except Exception:errors.append(unit)
   if errors:raise ValueError('Применение и откат не завершены. Резервная копия: '+str(backup)) from original
   detail=str(getattr(original,'stderr','') or getattr(original,'stdout','') or original).strip()[:1200]
   raise ValueError('Лимиты не применены; исходные файлы восстановлены. Причина: '+detail+' Резервная копия: '+str(backup)) from original
  return dict(read(),backup=str(backup),restarted=bool(active))
