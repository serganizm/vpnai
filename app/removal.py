"""Remote removal phases. Data stays on the servers; no credentials in receipts."""
COMMON=r'''import pathlib,json,shutil,os,sys,tarfile,datetime,subprocess,tempfile,io,re
P=pathlib.Path
state=P('/var/lib/ovpn-installer');receipt=P('/var/lib/ovpn-installer-removal.json')
role=DATA['role'];pair=DATA['pair']
def fail(code):
 print('VPNAI_DIAG:'+code,flush=True);raise SystemExit(1)
def allowed(name):
 if not isinstance(name,str):return False
 p=pathlib.PurePosixPath(name)
 if not p.is_absolute() or '..' in p.parts:return False
 return name in ('/root/menu.sh','/root/ovpn.sh','/root/ovpn-install-report.json','/etc/sysctl.d/90-ovpn-routing.conf','/etc/swanctl/conf.d/ovpn-gre.conf') or name.startswith(('/var/lib/ovpn-installer/','/etc/openvpn/server/','/etc/ovpn-routing/','/var/lib/ovpn-routing/','/var/lib/ovpn-links/','/root/ovpn-profiles/','/root/ovpn-downloads/','/usr/local/sbin/ovpn-','/usr/local/libexec/ovpn-','/etc/systemd/system/ovpn-','/etc/systemd/system/openvpn-server@ru','/etc/nginx/conf.d/ovpn-','/etc/nginx/sites-available/ovpn-','/etc/nginx/sites-enabled/ovpn-','/etc/letsencrypt/renewal-hooks/deploy/ovpn-'))
def paths():
 result=[]
 if role=='ru':result=[P(x) for x in ['/etc/openvpn/server/pki','/etc/openvpn/server/users.json','/etc/openvpn/server/tls-crypt.key','/etc/ovpn-routing','/var/lib/ovpn-routing','/root/ovpn-profiles','/root/ovpn-downloads','/var/lib/ovpn-links','/var/lib/ovpn-cert','/root/ovpn-install-report.json']]
 return result+[state]
def validate():
 if role not in ('ru','nl'):fail('CLEAN_ROLE')
 if state.is_symlink() or receipt.is_symlink():fail('CLEAN_PATH')
 if not (state/'owned.json').is_file():
  try:old=json.loads(receipt.read_text())
  except (OSError,ValueError):fail('CLEAN_OWNER')
  if old.get('role')!=role or old.get('pair')!=pair or old.get('complete') is not True:fail('CLEAN_OWNER')
  b=P(old.get('backup',''))
  if b.parent!=P('/root') or not b.name.startswith('ovpn-backup-') or b.is_symlink() or not b.is_file() or not tarfile.is_tarfile(b):fail('CLEAN_BACKUP')
  return {'already_removed':True,'backup':str(b),'finalize':state.exists()}
 try:
  if (state/'role').read_text().strip()!=role:fail('CLEAN_ROLE')
  owned=json.loads((state/'owned.json').read_text());baseline=json.loads((state/'baseline.json').read_text())
 except (OSError,ValueError):fail('CLEAN_OWNER')
 if not isinstance(owned,dict) or not isinstance(baseline.get('sysctl'),dict):fail('CLEAN_OWNER')
 for name,info in owned.items():
  if not allowed(name) or not isinstance(info,dict) or 'backup' not in info:fail('CLEAN_OWNER')
  path=P(name)
  if path.is_symlink() or path.is_dir():fail('CLEAN_PATH')
  if info['backup']:
   backup=P(info['backup'])
   try:backup.relative_to(state/'original')
   except ValueError:fail('CLEAN_BACKUP')
   if not backup.is_file() or backup.is_symlink():fail('CLEAN_BACKUP')
 for path in paths():
  if path.is_symlink():fail('CLEAN_PATH')
 if any(not shutil.which(name) for name in ('systemctl','ip','iptables','swanctl','sysctl')):fail('CLEAN_TOOLS')
 return {'already_removed':False,'owned':owned}
'''
PREFLIGHT=COMMON+r'''
meta=validate();print(json.dumps({'already_removed':meta['already_removed'],'backup':meta.get('backup'),'finalize':meta.get('finalize',False)}))
'''
BACKUP=COMMON+r'''
if DATA.get('force_snapshot') and DATA.get('allow_empty') and not (state/'owned.json').is_file():
 if state.is_symlink() or receipt.is_symlink() or any(path.exists() for path in paths()[:-1]):fail('CLEAN_OWNER')
 if receipt.exists():
  try:old=json.loads(receipt.read_text())
  except (OSError,ValueError):fail('CLEAN_OWNER')
  if old.get('role')!=role or old.get('pair')!=pair or old.get('complete') is not True:fail('CLEAN_OWNER')
 meta={'already_removed':True,'owned':{}}
else:meta=validate()
if meta['already_removed'] and not DATA.get('force_snapshot'):
 print(json.dumps({'backup':meta['backup'],'configured':False}));raise SystemExit(0)
snapshot=DATA.get('snapshot') or {'id':datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S-')+os.urandom(6).hex(),'created':datetime.datetime.now(datetime.timezone.utc).isoformat(),'pair':pair,'reason':'backup'}
if not isinstance(snapshot,dict) or snapshot.get('pair')!=pair or not re.fullmatch(r'[0-9]{8}-[0-9]{6}-[a-f0-9]{12}',snapshot.get('id','')):fail('CLEAN_BACKUP')
backup=P('/root')/('ovpn-backup-'+snapshot['id']+'.tar.gz')
userlock=None
if role=='ru' and os.name!='nt':
 import fcntl
 lockpath=P('/run/ovpn-user.lock');lockpath.parent.mkdir(parents=True,exist_ok=True)
 userlock=lockpath.open('a');fcntl.flock(userlock,fcntl.LOCK_SH)
try:
 fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as stream,tarfile.open(fileobj=stream,mode='w:gz') as archive:
  manifest=dict(snapshot,format=1,role=role,configured=not meta['already_removed'])
  body=json.dumps(manifest).encode();entry=tarfile.TarInfo('vpnai-backup.json');entry.size=len(body);entry.mode=0o600;archive.addfile(entry,io.BytesIO(body))
  seen=[]
  for path in paths()+[receipt]+[P(name) for name in meta.get('owned',{})]:
   if any(path==root or root in path.parents for root in seen) or not path.exists():continue
   seen.append(path);archive.add(path,arcname=str(path).lstrip('/'))
 if not tarfile.is_tarfile(backup):fail('CLEAN_BACKUP')
except (OSError,tarfile.TarError):fail('CLEAN_BACKUP')
if userlock:userlock.close()
print(json.dumps({'backup':str(backup),'configured':not meta['already_removed']}))
'''
CLEAN=COMMON+r'''
meta=validate()
if meta['already_removed']:
 if state.exists():shutil.rmtree(state)
 print('OK: already removed');raise SystemExit(0)
backup=P(DATA['backup'])
if backup.parent!=P('/root') or not backup.name.startswith('ovpn-backup-') or backup.is_symlink() or not backup.is_file() or not tarfile.is_tarfile(backup):fail('CLEAN_BACKUP')
# Always execute the current packaged rollback, never the stale server copy.
result=subprocess.run([sys.executable,'-c',DATA['rollback']])
if result.returncode:fail('CLEAN_ROLLBACK')
for path in paths()[:-1]:
 if path.is_symlink():fail('CLEAN_PATH')
 if path.is_dir():shutil.rmtree(path)
 else:path.unlink(missing_ok=True)
P('/usr/local/sbin/ovpn-install-rollback').unlink(missing_ok=True)
# Receipt is committed before removing ownership metadata, so a retry is safe.
receipt.parent.mkdir(parents=True,exist_ok=True)
tmp=None
try:
 with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=receipt.parent,prefix='.vpnai-removal-',delete=False) as f:
  tmp=P(f.name)
  if os.name!='nt':os.chmod(tmp,0o600)
  json.dump({'role':role,'pair':pair,'backup':str(backup),'complete':True},f);f.flush();os.fsync(f.fileno())
 tmp.replace(receipt);tmp=None
finally:
 if tmp:tmp.unlink(missing_ok=True)
shutil.rmtree(state)
print('OK')
'''
