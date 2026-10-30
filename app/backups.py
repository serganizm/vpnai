"""Paired backup catalogue and staged data restoration. No archive code is executed."""
import datetime,json,re,secrets
NAME=re.compile(r'ovpn-backup-[0-9]{8}-[0-9]{6}-[a-f0-9]{12}\.tar\.gz')
class BackupError(Exception):pass

def snapshot(pair,reason='backup'):
    now=datetime.datetime.now(datetime.timezone.utc)
    identity=now.strftime('%Y%m%d-%H%M%S-')+secrets.token_hex(6)
    return {'id':identity,'filename':'ovpn-backup-'+identity+'.tar.gz','created':now.isoformat(),'pair':dict(pair),'reason':reason}

REMOTE=r'''import pathlib,tarfile,json,re,hashlib,os,shutil,tempfile,subprocess
P=pathlib.Path
role=DATA['role'];pair=DATA['pair'];action=DATA['op']
class BadArchive(Exception):pass
def bad(code):raise BadArchive(code)
def allowed(name):
 if name=='vpnai-backup.json':return True
 if name=='var/lib/ovpn-installer-removal.json':return True
 if name=='var/lib/ovpn-installer' or name.startswith('var/lib/ovpn-installer/'):return True
 common={'etc/sysctl.d/90-ovpn-routing.conf','etc/swanctl/conf.d/ovpn-gre.conf','usr/local/sbin/ovpn-network','usr/local/sbin/ovpn-tcp-network','usr/local/sbin/ovpn-install-rollback','usr/local/sbin/ovpn-acme-proxy.py','etc/systemd/system/ovpn-network.service','etc/systemd/system/ovpn-tcp-network.service','etc/systemd/system/ovpn-acme-proxy.service'}
 if name in common:return True
 if role!='ru':return False
 if name in ('root/menu.sh','root/ovpn.sh','root/ovpn-install-report.json'):return True
 return any(name==base or name.startswith(base+'/') for base in ('etc/openvpn/server','etc/ovpn-routing','var/lib/ovpn-routing','var/lib/ovpn-links','var/lib/ovpn-cert','root/ovpn-profiles','root/ovpn-downloads')) or name.startswith(('usr/local/sbin/ovpn-','usr/local/libexec/ovpn-','etc/systemd/system/ovpn-','etc/systemd/system/openvpn-server@ru','etc/nginx/conf.d/ovpn-','etc/nginx/sites-available/ovpn-','etc/nginx/sites-enabled/ovpn-','etc/letsencrypt/renewal-hooks/deploy/ovpn-'))
def normal(name):
 q=pathlib.PurePosixPath(name)
 if q.is_absolute() or '..' in q.parts or '\\' in name or any(ord(c)<32 for c in name):bad('PATH')
 result=q.as_posix().rstrip('/')
 if not allowed(result):bad('PATH')
 return result
def archive_path(name):
 if not isinstance(name,str) or not re.fullmatch(r'ovpn-backup-[0-9]{8}-[0-9]{6}-[a-f0-9]{12}\.tar\.gz',name):bad('NAME')
 f=P('/root')/name
 if f.is_symlink() or not f.is_file():bad('MISSING')
 return f
def index(archive):
 result={};total=0
 for member in archive.getmembers():
  name=normal(member.name)
  if not member.isdir() and not member.isfile():bad('LINK')
  total+=member.size
  if len(result)>100000 or total>2147483648 or member.size>134217728:bad('SIZE')
  if name in result:bad('DUPLICATE')
  result[name]=member
 return result
def text(archive,entries,name,required=True):
 m=entries.get(name)
 if not m:
  if required:bad('INCOMPLETE')
  return ''
 if not m.isfile() or m.size>2097152:bad('SIZE')
 return archive.extractfile(m).read().decode('utf-8')
def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as stream:
  for block in iter(lambda:stream.read(65536),b''):h.update(block)
 return h.hexdigest()
def inspect(name,private=False):
 f=archive_path(name);stat=f.stat()
 with tarfile.open(f,'r:gz') as archive:
  entries=index(archive)
  manifest_raw=text(archive,entries,'vpnai-backup.json',False);manifest=json.loads(manifest_raw) if manifest_raw else {}
  if not manifest:bad('FORMAT')
  if manifest.get('configured') is False:bad('EMPTY')
  if manifest and (manifest.get('format')!=1 or manifest.get('role')!=role or manifest.get('pair')!=pair or not isinstance(manifest.get('id'),str)):bad('PAIR')
  if not re.fullmatch(r'[0-9]{8}-[0-9]{6}-[a-f0-9]{12}',manifest['id']) or name!='ovpn-backup-'+manifest['id']+'.tar.gz':bad('FORMAT')
  if text(archive,entries,'var/lib/ovpn-installer/role').strip()!=role:bad('ROLE')
  owned=json.loads(text(archive,entries,'var/lib/ovpn-installer/owned.json'))
  baseline=json.loads(text(archive,entries,'var/lib/ovpn-installer/baseline.json'))
  if not isinstance(owned,dict) or not isinstance(baseline.get('sysctl'),dict):bad('INCOMPLETE')
  for path,info in owned.items():
   if not isinstance(path,str) or not path.startswith('/') or not allowed(normal(path[1:])) or not isinstance(info,dict):bad('PATH')
   if info.get('backup'):
    original=info['backup']
    if not isinstance(original,str) or not original.startswith('/var/lib/ovpn-installer/original/'):bad('PATH')
    if normal(original[1:]) not in entries:bad('INCOMPLETE')
  swan=text(archive,entries,'etc/swanctl/conf.d/ovpn-gre.conf')
  secrets=re.findall(r'\bsecret\s*=\s*([^\s{}]+)',swan)
  if len(secrets)!=1:bad('PAIR')
  secret=secrets[0].strip('"\'')
  if not re.fullmatch(r'[A-Za-z0-9+/=_-]{32,256}',secret):bad('PAIR')
  local=pair['ru_ip'] if role=='ru' else pair['nl_ip'];remote=pair['nl_ip'] if role=='ru' else pair['ru_ip']
  if not re.search(r'\blocal_addrs\s*=\s*'+re.escape(local)+r'\s',swan) or not re.search(r'\bremote_addrs\s*=\s*'+re.escape(remote)+r'\s',swan):bad('PAIR')
  state=None;settings={}
  if role=='ru':
   state=json.loads(text(archive,entries,'var/lib/ovpn-installer/state.json'))
   cfg=state.get('config',{})
   if any(cfg.get(k)!=pair[k] for k in ('ru_ip','nl_ip')) or state.get('psk')!=secret:bad('PAIR')
   if state.get('version')!=2:bad('FORMAT')
   if state.get('complete') is not True:bad('INCOMPLETE')
   if cfg.get('routing_mode') not in ('split','full_mixed','full_nl') or cfg.get('auth_mode') not in ('password','certificate'):bad('MODES')
   if state.get('complete') is True:
    for required in ('etc/openvpn/server/users.json','etc/openvpn/server/pki/ca.crt','etc/openvpn/server/pki/private/ca.key','etc/openvpn/server/pki/private/ru-server.key','etc/openvpn/server/tls-crypt.key'):
     if required not in entries:bad('INCOMPLETE')
   settings={k:cfg.get(k) for k in ('routing_mode','auth_mode','ovpn_port','initial_user')}
  fingerprint=hashlib.sha256((secret+'\0'+pair['ru_ip']+'\0'+pair['nl_ip']).encode()).hexdigest()
  # Read through gzip's trailer so truncated/corrupt archives do not pass validation.
  for _ in iter(lambda:archive.fileobj.read(65536),b''):pass
 result={'name':name,'valid':True,'size':stat.st_size,'mtime':stat.st_mtime,'snapshot_id':manifest.get('id'),'created':manifest.get('created'),'fingerprint':fingerprint,'sha256':sha(f),'settings':settings,'has_users':'etc/openvpn/server/users.json' in entries}
 if f.stat().st_mtime_ns!=stat.st_mtime_ns or f.stat().st_size!=stat.st_size:bad('CHANGED')
 if private:result['state']=state
 return result

def data_member(name):
 return role=='ru' and any(name==base or name.startswith(base+'/') for base in ('etc/openvpn/server/pki','etc/openvpn/server/users.json','etc/openvpn/server/tls-crypt.key','etc/ovpn-routing','var/lib/ovpn-routing','root/ovpn-profiles'))
def stage_path():
 token=DATA.get('stage')
 if not isinstance(token,str) or not re.fullmatch('[a-f0-9]{24}',token):bad('STAGE')
 root=P('/root')/('.vpnai-restore-'+token)
 if root.is_symlink():bad('PATH')
 return root
try:
 if action=='list':
  rows=[]
  files=sorted(P('/root').glob('ovpn-backup-*.tar.gz'),key=lambda f:f.stat().st_mtime,reverse=True)[:100]
  for f in files:
   if not re.fullmatch(r'ovpn-backup-[0-9]{8}-[0-9]{6}-[a-f0-9]{12}\.tar\.gz',f.name):continue
   try:rows.append(inspect(f.name))
   except (BadArchive,OSError,ValueError,tarfile.TarError,UnicodeError,EOFError) as error:
    if isinstance(error,BadArchive) and str(error) in ('FORMAT','EMPTY'):continue
    rows.append({'name':f.name,'valid':False,'reason':str(error) if isinstance(error,BadArchive) else 'INVALID','mtime':f.stat().st_mtime,'size':f.stat().st_size})
  print(json.dumps(rows))
 elif action=='inspect':print(json.dumps(inspect(DATA['name'],True)))
 elif action=='stage':
  info=inspect(DATA['name'],True)
  if info['sha256']!=DATA['sha256']:bad('CHANGED')
  with tarfile.open(archive_path(DATA['name']),'r:gz') as archive:
   needed=sum(member.size for name,member in index(archive).items() if data_member(name) and member.isfile())
  if shutil.disk_usage(P('/root')).free<needed*2+16777216:bad('SPACE')
  root=stage_path();root.mkdir(mode=0o700);payload=root/'data';payload.mkdir(mode=0o700)
  try:
   with tarfile.open(archive_path(DATA['name']),'r:gz') as archive:
    for name,member in index(archive).items():
     if not data_member(name):continue
     target=payload/name
     if member.isdir():target.mkdir(mode=0o700,parents=True,exist_ok=True)
     else:
      target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
      with archive.extractfile(member) as source,target.open('xb') as dest:shutil.copyfileobj(source,dest,65536)
      target.chmod(0o600)
   if sha(archive_path(DATA['name']))!=info['sha256']:bad('CHANGED')
   (root/'plan.json').write_text(json.dumps({'role':role,'pair':pair,'name':info['name'],'sha256':info['sha256']}));(root/'plan.json').chmod(0o600)
  except BaseException:shutil.rmtree(root);raise
  print(json.dumps({'stage':DATA['stage'],'state':info.get('state')}))
 elif action=='apply':
  root=stage_path();plan=json.loads((root/'plan.json').read_text())
  if plan.get('role')!=role or plan.get('pair')!=pair or plan.get('sha256')!=DATA['sha256']:bad('STAGE')
  # Only VPN data is restored. Executables and service definitions come from this installer.
  for source in sorted((root/'data').rglob('*')):
   relative=source.relative_to(root/'data').as_posix()
   if source.is_symlink():bad('PATH')
   if source.is_dir() and not data_member(relative):continue
   if not data_member(relative):bad('PATH')
   target=P('/'+relative)
   logical=pathlib.PurePosixPath('/'+relative)
   for parent in [logical]+list(logical.parents):
    if P(str(parent)).is_symlink():bad('PATH')
   if source.is_dir():target.mkdir(mode=0o700,parents=True,exist_ok=True)
   else:
    target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=target.parent,delete=False) as stream:
     temp=P(stream.name)
     try:
      with source.open('rb') as src:shutil.copyfileobj(src,stream,65536)
      stream.flush();os.fsync(stream.fileno())
     except BaseException:temp.unlink(missing_ok=True);raise
    temp.chmod(0o600);temp.replace(target)
  print('OK')
 elif action=='discard':
  root=stage_path()
  if root.exists():shutil.rmtree(root)
  print('OK')
 else:bad('ACTION')
except (BadArchive,OSError,ValueError,tarfile.TarError,UnicodeError,EOFError):
 print('VPNAI_DIAG:BACKUP_INVALID',flush=True);raise SystemExit(1)
'''

def catalogue(ru_rows,nl_rows):
    result=[]
    for row in ru_rows:
        public={k:row.get(k) for k in ('name','size','mtime','created','settings','has_users')};public.update(available=False,counterpart=None)
        if not row.get('valid'):public['reason']='Архив неполный, повреждён или не относится к этой паре серверов.';result.append(public);continue
        candidates=[other for other in nl_rows if other.get('valid') and other.get('fingerprint')==row.get('fingerprint')]
        if not row.get('snapshot_id'):public['reason']='Поддерживается только новый парный формат архивов.';result.append(public);continue
        candidates=[other for other in candidates if other.get('snapshot_id')==row['snapshot_id'] and other.get('name')==row['name']]
        if len(candidates)==1:public.update(available=True,counterpart=candidates[0]['name'])
        else:public['reason']='Соответствующий архив на зарубежном сервере не найден однозначно.'
        result.append(public)
    return result

def remote(ep,pair,op,**values):
    return ep.python(REMOTE,dict(role=ep.role,pair=pair,op=op,**values))

def find_pair(ru,nl,pair,name):
    ru_rows=json.loads(remote(ru,pair,'list'));nl_rows=json.loads(remote(nl,pair,'list'))
    entry=next((item for item in catalogue(ru_rows,nl_rows) if item['name']==name),None)
    if not entry or not entry['available']:raise BackupError('Выбранный архив не имеет проверенной пары на зарубежном сервере. Обновите список архивов.')
    return next(row for row in ru_rows if row['name']==name),next(row for row in nl_rows if row['name']==entry['counterpart'])
