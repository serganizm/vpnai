#!/usr/bin/python3
"""Reuse verified certificates and renew through NL, with direct fallback."""
import datetime,json,os,pathlib,ssl,subprocess,sys,tempfile,urllib.request,fcntl
IP='@@RU_IP@@'
PROXY='http://@@GRE_NL@@:18765'
DIRECTORY='https://acme-v02.api.letsencrypt.org/directory'
CERT=pathlib.Path('/etc/letsencrypt/live/ovpn-links/fullchain.pem')
KEY=pathlib.Path('/etc/letsencrypt/live/ovpn-links/privkey.pem')
LINEAGE=pathlib.Path('/etc/letsencrypt/renewal/ovpn-links.conf')
STATUS=pathlib.Path('/var/lib/ovpn-cert/status.json')
CERTBOT='/opt/ovpn-certbot/bin/certbot'
HOOK='/etc/letsencrypt/renewal-hooks/deploy/ovpn-nginx.sh'
def command(args,**kwargs):return subprocess.run(args,capture_output=True,timeout=30,**kwargs)
def reusable():
 try:
  if not CERT.is_file() or not KEY.is_file() or not LINEAGE.is_file():return False
  checks=[['openssl','x509','-in',str(CERT),'-noout','-checkend','86400'],['openssl','x509','-in',str(CERT),'-noout','-checkip',IP],['openssl','verify','-CAfile','/etc/ssl/certs/ca-certificates.crt','-untrusted',str(CERT),str(CERT)]]
  if any(command(args).returncode for args in checks):return False
  public=command(['openssl','x509','-in',str(CERT),'-pubkey','-noout'])
  certificate=command(['openssl','pkey','-pubin','-outform','DER'],input=public.stdout)
  private=command(['openssl','pkey','-in',str(KEY),'-pubout','-outform','DER'])
  return public.returncode==certificate.returncode==private.returncode==0 and bool(certificate.stdout) and certificate.stdout==private.stdout
 except (OSError,subprocess.TimeoutExpired):return False

def transport():
 for name,proxy in [('nl',PROXY),('direct',None)]:
  try:
   handler=urllib.request.ProxyHandler({'https':proxy} if proxy else {})
   opener=urllib.request.build_opener(handler,urllib.request.HTTPSHandler(context=ssl.create_default_context()))
   with opener.open(DIRECTORY,timeout=12) as response:
    data=json.loads(response.read(262144))
    if response.status==200 and isinstance(data,dict) and 'newNonce' in data and 'newAccount' in data:return name
  except (OSError,ValueError):pass
 return None

def environment(route):
 env=os.environ.copy()
 for key in list(env):
  if key.lower() in ('http_proxy','https_proxy','all_proxy','no_proxy'):del env[key]
 if route=='nl':env['HTTPS_PROXY']=PROXY
 return env

def status(action,result,route=None):
 STATUS.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 payload={'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'action':action,'status':result,'transport':route}
 temp=None
 try:
  with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=STATUS.parent,delete=False) as f:
   temp=pathlib.Path(f.name);os.chmod(temp,0o600);json.dump(payload,f);f.flush();os.fsync(f.fileno())
  temp.replace(STATUS);temp=None
 finally:
  if temp:temp.unlink(missing_ok=True)
 print(json.dumps(payload),flush=True)

def manage(action):
 if action=='ensure' and reusable():status(action,'reused');return 0
 route=transport()
 if action=='probe':print(json.dumps({'available':bool(route),'transport':route}));return 0
 if not route:status(action,'network-unavailable');print('VPNAI_DIAG:HTTPS_NETWORK');return 1
 common=[CERTBOT,'--non-interactive','--cert-name','ovpn-links']
 if action=='renew':args=common+['renew','--preferred-profile','shortlived','--quiet','--no-random-sleep-on-renew','--deploy-hook',HOOK]
 elif action=='ensure':args=common+['certonly','--agree-tos','--register-unsafely-without-email','--preferred-profile','shortlived','--webroot','-w','/var/www/ovpn-acme','--ip-address',IP,'--keep-until-expiring','--deploy-hook',HOOK]
 else:raise ValueError('action')
 # Network retries use the existing lineage; never force a certificate issuance.
 for attempt in range(2):
  try:result=subprocess.run(args,env=environment(route),capture_output=True,text=True,timeout=300)
  except (OSError,subprocess.TimeoutExpired):result=None
  if result is not None and result.returncode==0:status(action,'ok',route);return 0
  message=((result.stdout or '')+(result.stderr or '')).lower() if result else ''
  if 'ratelimit' in message or 'too many certificates' in message:
   status(action,'rate-limited',route);print('VPNAI_DIAG:HTTPS_RATE');return 1
  if 'unauthorized' in message or 'invalid response from' in message:
   status(action,'challenge-failed',route);print('VPNAI_DIAG:HTTPS_CHALLENGE');return 1
  if attempt==0 and (result is None or any(word in message for word in ('timed out','connectionerror','connection refused','connection reset'))):
   route=transport()
   if route:continue
  break
 status(action,'failed',route);print('VPNAI_DIAG:HTTPS_ISSUE');return 1

def main():
 action=sys.argv[1] if len(sys.argv)==2 else ''
 if action not in ('ensure','renew','probe'):raise SystemExit('Use ensure, renew or probe')
 if action=='probe':return manage(action)
 with open('/run/ovpn-cert-manage.lock','a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  return manage(action)
if __name__=='__main__':raise SystemExit(main())
