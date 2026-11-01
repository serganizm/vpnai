"""Server-side policy and atomic UDP/TCP session accounting. Executed on Linux."""
import contextlib,hashlib,json,os,pathlib,re,secrets,subprocess,sys,time
POLICY=pathlib.Path('/etc/openvpn/server/connection-limits.json')
RUNTIME=pathlib.Path('/run/vpnai-session-limits')
ROUTE_HOOK='/usr/local/libexec/ovpn-split-connect'
CERTS=pathlib.Path('/etc/openvpn/server/pki/issued')
def certificate(name):
 try:return hashlib.sha256((CERTS/(name+'.crt')).read_bytes()).hexdigest()
 except OSError:return None
def limit(value,inherit=False):
 if inherit and value is None:return None
 if type(value) is not int or not 0<=value<=1000:raise ValueError('Лимит: целое число от 1 до 1000, либо 0 для безлимита.')
 return value
def policy(required=False):
 if not POLICY.exists():
  if required:raise ValueError('Не найден файл лимитов; подключение отклонено.')
  return {'version':1,'default':0,'users':{}}
 value=json.loads(POLICY.read_text());limit(value['default'])
 if value.get('version')!=1 or not isinstance(value.get('users'),dict):raise ValueError('Повреждён файл лимитов.')
 for name,n in value['users'].items():
  if not re.fullmatch(r'[A-Za-z0-9_-]{1,48}',name):raise ValueError('Некорректный пользователь в лимитах.')
  limit(n)
 return value
def atomic(path,value):
 path=pathlib.Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 tmp=path.with_name(path.name+'.'+secrets.token_hex(8)+'.tmp')
 try:
  with open(tmp,'x',encoding='utf-8') as stream:
   os.chmod(tmp,0o600);json.dump(value,stream,ensure_ascii=False);stream.flush();os.fsync(stream.fileno())
  os.replace(tmp,path)
 finally:
  with contextlib.suppress(FileNotFoundError):tmp.unlink()
def process_stamp(pid):
 try:
  text=pathlib.Path('/proc',str(pid),'stat').read_text();return text.rsplit(')',1)[1].split()[19]
 except (OSError,IndexError):return None
def identity(env,pid=None):
 name=env.get('common_name','')
 if not re.fullmatch(r'[A-Za-z0-9_-]{1,48}',name):raise ValueError('Некорректное имя сертификата.')
 pid=os.getppid() if pid is None else pid;stamp=process_stamp(pid)
 if stamp is None:raise ValueError('Не определён процесс OpenVPN.')
 values=[str(pid),stamp,env.get('dev',''),name,env.get('ifconfig_pool_remote_ip',''),env.get('time_unix','')]
 if not all(values[i] for i in (2,4,5)):raise ValueError('Не определён сеанс OpenVPN.')
 return hashlib.sha256(json.dumps(values).encode()).hexdigest(),{'name':name,'pid':pid,'stamp':stamp,'created':time.time()}
@contextlib.contextmanager
def ledger():
 import fcntl
 RUNTIME.mkdir(mode=0o700,parents=True,exist_ok=True);RUNTIME.chmod(0o700)
 with open(RUNTIME/'lock','a') as lock:
  os.chmod(RUNTIME/'lock',0o600);fcntl.flock(lock,fcntl.LOCK_EX)
  path=RUNTIME/'sessions.json';rows=json.loads(path.read_text()) if path.exists() else {}
  if not isinstance(rows,dict):raise ValueError('Повреждён учёт подключений.')
  rows={k:v for k,v in rows.items() if process_stamp(v['pid'])==v['stamp']}
  yield rows
  atomic(path,rows)
def reserve(env,pid=None):
 key,row=identity(env,pid)
 with ledger() as rows:
  p=policy(required=True);maximum=p['users'].get(row['name'],p['default']) if p.get('identities',{}).get(row['name'])==certificate(row['name']) and certificate(row['name']) is not None else p['default']
  if key in rows:return key,False
  if maximum and sum(v['name']==row['name'] for v in rows.values())>=maximum:raise ValueError('Достигнут лимит одновременных подключений.')
  rows[key]=row
 return key,True
def release(key):
 with ledger() as rows:rows.pop(key,None)
def hook(action,args):
 if action=='disconnect':
  key,_=identity(os.environ);release(key);return
 key,created=reserve(os.environ)
 try:
  if action=='connect':subprocess.run([ROUTE_HOOK,*args],check=True,timeout=30)
 except BaseException:
  if created:release(key)
  raise
if __name__=='__main__':
 try:
  if len(sys.argv)<2 or sys.argv[1] not in ('connect','connect-full','disconnect'):raise ValueError('Unknown hook action')
  hook(sys.argv[1],sys.argv[2:])
 except Exception as error:
  print('VPNAI: '+str(error),file=sys.stderr);raise SystemExit(1)
