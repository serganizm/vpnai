#!/usr/bin/env python3
"""Two-host OpenVPN/GRE/IPsec installer. Run on RU, configure NL via SSH."""
import argparse,base64,datetime,hashlib,ipaddress,json,os,pathlib,re,secrets,shlex,subprocess,sys
try:
    import fcntl
except ImportError:
    fcntl=None
ROOT=pathlib.Path(__file__).resolve().parent
STATE=pathlib.Path('/var/lib/ovpn-installer/state.json')
class InstallError(RuntimeError):pass

def run(args,stdin=None,quiet=False):
    r=subprocess.run(args,input=stdin,text=True,stdout=subprocess.PIPE if quiet else None,stderr=subprocess.PIPE if quiet else None)
    if r.returncode:
        # Do not echo command arguments: a remote payload may contain secrets.
        raise InstallError('Команда завершилась с ошибкой (код %s). %s'%(r.returncode,(r.stderr or '')[-1200:] if quiet else 'Смотрите вывод выше.'))
    return r.stdout or ''

class Endpoint:
    def __init__(self,role,host=None,port=22,key=None,control=None):
        self.role=role;self.host=host
        self.ssh=['ssh','-p',str(port),'-o','ControlMaster=auto','-o','ControlPersist=600','-o','ControlPath='+str(control),'-o','ServerAliveInterval=15','-o','ConnectTimeout=15']
        if key:self.ssh+=['-i',key]
    def shell(self,script,quiet=False):
        return run(self.ssh+[self.host,'bash -s'] if self.host else ['bash','-s'],script,quiet)
    def python(self,code,data=None):
        wrapper='import json,sys\nDATA=json.load(sys.stdin)\n'+code
        payload=json.dumps(data)
        args=self.ssh+[self.host,'python3 -c '+shlex.quote(wrapper)] if self.host else ['python3','-c',wrapper]
        return run(args,payload,True)
    def connect(self):
        if self.host:
            # Interactive SSH first: host fingerprint and password use the terminal, never stored.
            run(self.ssh+[self.host,'test "$(id -u)" = 0 && command -v python3 >/dev/null'])
    def inventory(self):
        code='''import subprocess,os,pathlib
if os.geteuid()!=0:raise SystemExit('Нужен root на обоих VPS')
def c(*a):return subprocess.run(a,capture_output=True,text=True).stdout.strip()
osr={}
for line in pathlib.Path('/etc/os-release').read_text().splitlines():
 if '=' in line:
  k,v=line.split('=',1);osr[k]=v.strip('"')
print(json.dumps({'os':osr,'addr':json.loads(c('ip','-j','-4','addr')),'routes':json.loads(c('ip','-j','-4','route')),'routes6':json.loads(c('ip','-j','-6','route')),'links':json.loads(c('ip','-j','link')),'sockets':c('ss','-lntu'),'rules':c('ip','rule'),'table':c('ip','route','show','table','310'),'swan':c('systemctl','is-active','strongswan'),'xfrm':c('ip','xfrm','policy'),'sysctl':{k:c('sysctl','-n',k) for k in ['net.ipv4.ip_forward','net.ipv4.conf.all.rp_filter','net.ipv4.conf.default.rp_filter']},'reserved_files':[str(p) for p in [pathlib.Path('/root/ovpn.sh'),pathlib.Path('/root/menu.sh'),pathlib.Path('/usr/local/sbin/ovpn-user'),pathlib.Path('/etc/openvpn/server/ru.conf'),pathlib.Path('/etc/swanctl/conf.d/ovpn-gre.conf'),pathlib.Path('/usr/local/sbin/ovpn-network')] if p.exists()],'managed':pathlib.Path('/var/lib/ovpn-installer/owned.json').exists()}))
'''
        return json.loads(self.python(code))
    def write(self,path,text,mode=0o600,preserve=False):
        code='''import pathlib,base64,shutil
p=pathlib.Path(DATA['path']);state=pathlib.Path('/var/lib/ovpn-installer');state.mkdir(mode=0o700,parents=True,exist_ok=True)
m=state/'owned.json';owned=json.loads(m.read_text()) if m.exists() else {}
if DATA['preserve'] and p.exists():
 print('preserved');raise SystemExit(0)
if str(p) not in owned:
 b=state/'original'/str(p).lstrip('/')
 if p.exists():
  if p.is_symlink():raise SystemExit('Refusing to replace a symlink: '+str(p))
  b.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,b);owned[str(p)]={'backup':str(b)}
 else:owned[str(p)]={'backup':None}
 m.write_text(json.dumps(owned));m.chmod(0o600)
p.parent.mkdir(parents=True,exist_ok=True)
t=p.with_name(p.name+'.install-new');t.write_bytes(base64.b64decode(DATA['body']));t.chmod(DATA['mode']);t.replace(p)
'''
        self.python(code,{'path':path,'body':base64.b64encode(text.encode()).decode(),'mode':mode,'preserve':preserve})

def validate(c):
    c.setdefault('tcp_net','10.79.0.0/24')
    for k in ['ru_ip','nl_ip']:
        try:a=ipaddress.ip_address(c[k])
        except ValueError:raise InstallError('Неверный '+k)
        if a.version!=4 or not a.is_global:raise InstallError(k+': нужен публичный IPv4')
    if c['ru_ip']==c['nl_ip']:raise InstallError('Серверы должны иметь разные IP')
    if not 1024<=c['ovpn_port']<=65535 or c['ovpn_port'] in (4500,):raise InstallError('OpenVPN UDP-порт: 1024..65535, кроме 4500')
    v=ipaddress.ip_network(c['vpn_net'],strict=True);g=ipaddress.ip_network(c['gre_net'],strict=True)
    private=[ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
    if v.version!=4 or v.prefixlen!=24 or not any(v.subnet_of(n) for n in private):raise InstallError('VPN-сеть должна быть частной IPv4 /24')
    if g.version!=4 or g.prefixlen!=30 or not any(g.subnet_of(n) for n in private):raise InstallError('GRE-сеть должна быть частной IPv4 /30')
    if v.overlaps(g):raise InstallError('VPN и GRE сети пересекаются')
    t=ipaddress.ip_network(c['tcp_net'],strict=True)
    if t.version!=4 or t.prefixlen!=24 or not any(t.subnet_of(n) for n in private):raise InstallError('TCP-сеть должна быть частной IPv4 /24')
    if t.overlaps(v) or t.overlaps(g):raise InstallError('TCP-сеть пересекается с UDP/GRE')
    if not re.fullmatch(r'root@(?:[A-Za-z0-9][A-Za-z0-9.-]*|\d+\.\d+\.\d+\.\d+)',c['nl_host']):raise InstallError('SSH-хост должен иметь вид root@IP или root@hostname')
    if not 1<=c['ssh_port']<=65535:raise InstallError('Неверный SSH-порт')
    if c.get('initial_user') and not re.fullmatch(r'[A-Za-z0-9_-]{1,48}',c['initial_user']):raise InstallError('Недопустимый логин')
    return c

def tokens(c,role):
    v=ipaddress.ip_network(c['vpn_net']);g=ipaddress.ip_network(c['gre_net'])
    return {'RU_IP':c['ru_ip'],'NL_IP':c['nl_ip'],'TCP_NET':c.get('tcp_net','10.79.0.0/24'),'TCP_SERVER':str(ipaddress.ip_network(c.get('tcp_net','10.79.0.0/24')).network_address)+' 255.255.255.0','VPN_NET':str(v),'VPN_SERVER':str(v.network_address)+' '+str(v.netmask),'GRE_RU':str(g[1]),'GRE_NL':str(g[2]),'GRE_RU_ADDR':str(g[1])+'/30','GRE_NL_ADDR':str(g[2])+'/30','OVPN_PORT':str(c['ovpn_port']),'RU_DEV':c.get('ru_dev','eth0'),'NL_DEV':c.get('nl_dev','eth0')}

def render(text,c,role):
    for key,value in tokens(c,role).items():text=text.replace('@@'+key+'@@',value)
    if re.search(r'@@[A-Z_]+@@',text):raise InstallError('В шаблоне остались неизвестные параметры')
    return text

def verify_payload():
    m=json.loads((ROOT/'MANIFEST.json').read_text())
    for name,digest in m.items():
        p=ROOT/name
        if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=digest:raise InstallError('Повреждён файл установщика: '+name)

def check_templates(c):
    import ast
    count=0
    for role in ('ru','nl'):
        for p in (ROOT/'payload'/role).rglob('*'):
            if not p.is_file():continue
            text=render(p.read_text(),c,role)
            if text.startswith('#!/usr/bin/python3'):ast.parse(text)
            if text.startswith(('#!/bin/bash','#!/bin/sh')):
                run(['bash','-n'],text,True)
            count+=1
    print('Шаблоны проверены: %d файлов; подключений к серверам и изменений не было.'%count)

NGINX_REUSE_PROBE=r'''import pathlib,json,subprocess,re
p=pathlib.Path
ok=False
try:
 receipt=json.loads(p('/var/lib/ovpn-installer-removal.json').read_text())
 pair={k:DATA[k] for k in ('ru_ip','nl_ip')}
 sites=list(p('/etc/nginx/sites-enabled').iterdir())
 stock=all(x.name=='default' and x.resolve()==p('/etc/nginx/sites-available/default') for x in sites)
 stock=stock and not list(p('/etc/nginx/conf.d').glob('*.conf'))
 sockets=subprocess.run(['ss','-Hltnp','sport = :80'],capture_output=True,text=True,timeout=10)
 listeners=sockets.stdout.splitlines()
 nginx_only=sockets.returncode==0 and bool(listeners) and all(re.findall(r'\("([^"]+)"',line) and set(re.findall(r'\("([^"]+)"',line))=={'nginx'} for line in listeners)
 config=subprocess.run(['nginx','-T'],capture_output=True,text=True,timeout=10)
 clean='\n'.join(line.split('#',1)[0] for line in config.stdout.splitlines())
 names=re.findall(r'\bserver_name\s+([^;]+);',clean)
 default_names=all(set(name.split())<={'_', '""'} for name in names)
 ok=receipt.get('complete') is True and receipt.get('role')=='ru' and receipt.get('pair')==pair and stock and nginx_only and config.returncode==0 and default_names
except (OSError,ValueError,subprocess.TimeoutExpired):pass
print(json.dumps(bool(ok)))
'''

def preflight(c,ep,inv,resume):
    osr=inv['os'];supported=(osr.get('ID')=='ubuntu' and osr.get('VERSION_ID') in ('24.04','26.04')) or (osr.get('ID')=='debian' and osr.get('VERSION_ID') in ('12','13'))
    if not supported:raise InstallError(ep.role+': поддерживаются Ubuntu 24.04/26.04, Debian 12/13')
    expected=c[ep.role+'_ip']
    assigned={x['local'] for iface in inv['addr'] for x in iface.get('addr_info',[]) if x.get('family')=='inet'}
    if expected not in assigned:raise InstallError(ep.role+': публичный IP должен быть назначен интерфейсу VPS напрямую; NAT пока не поддерживается')
    defaults=[r for r in inv['routes'] if r.get('dst')=='default' and r.get('dev')]
    if len(defaults)!=1:raise InstallError(ep.role+': требуется один однозначный основной маршрут')
    dev=defaults[0]['dev']
    if not re.fullmatch(r'[A-Za-z0-9_.:-]+',dev):raise InstallError('Недопустимое имя интерфейса')
    c[ep.role+'_dev']=dev
    inv['sysctl']['net.ipv4.conf.'+dev+'.rp_filter']=ep.python("import subprocess; print(subprocess.check_output(['sysctl','-n',DATA],text=True).strip())",'net.ipv4.conf.'+dev+'.rp_filter').strip()
    for r in inv['routes']:
        if not r.get('dst') or r['dst']=='default':continue
        try:net=ipaddress.ip_network(r['dst'],strict=False)
        except ValueError:continue
        if any(net.overlaps(ipaddress.ip_network(c[k])) for k in ('vpn_net','gre_net','tcp_net')) and not (resume and inv['managed']):raise InstallError(ep.role+': выбранная подсеть пересекается с существующим маршрутом '+str(net))
    if not (resume and inv['managed']):
        for route in inv.get('routes6',[]):
            try:n=ipaddress.ip_network(route.get('dst',''),strict=False)
            except ValueError:continue
            if n.version==6 and n.prefixlen and any(n.overlaps(ipaddress.ip_network(x)) for x in ['fd77:77:77::/64','fd79:79:79::/64']):raise InstallError(ep.role+': IPv6-префикс OpenVPN уже используется')
        if inv.get('reserved_files'):raise InstallError(ep.role+': уже есть чужие файлы OpenVPN/каскада: '+', '.join(inv['reserved_files']))
        for name in ['gre-nl','tun-ovpn','tun-ovpn-tcp']:
            if any(x['ifname']==name for x in inv['links']):raise InstallError(ep.role+': интерфейс '+name+' уже используется')
        if inv['table'] or '10310:' in inv['rules']:raise InstallError(ep.role+': таблица 310 или правило 10310 уже используется')
        if inv['swan']=='active' or 'proto esp' in inv['xfrm']:raise InstallError(ep.role+': уже существует IPsec. Установщик не изменяет чужой strongSwan')
        reuse_nginx=None
        for line in inv['sockets'].splitlines():
            port=re.search(r':(\d+)\s',line)
            if not port:continue
            n=int(port[1]);proto=line.split()[0]
            if ep.role=='ru' and proto.startswith('tcp') and n==80:
                if reuse_nginx is None:reuse_nginx=json.loads(ep.python(NGINX_REUSE_PROBE,{k:c[k] for k in ('ru_ip','nl_ip')})) is True
                if reuse_nginx:continue
            if ep.role=='ru' and ((proto.startswith('tcp') and n in (80,443,8765,c['ovpn_port'])) or (proto.startswith('udp') and n==c['ovpn_port'])):raise InstallError('RU: занят нужный порт '+str(n))
            if ep.role=='nl' and proto.startswith('tcp') and n==18765:raise InstallError('NL: занят служебный ACME-порт 18765')
            if proto.startswith('udp') and n in (500,4500):raise InstallError(ep.role+': IKE-порты заняты')
    # Save baseline once; no secrets in this inventory.
    ep.write('/var/lib/ovpn-installer/baseline.json',json.dumps(inv),preserve=True)

def swan(c,role,psk):
    local=c[role+'_ip'];remote=c['nl_ip' if role=='ru' else 'ru_ip']
    return f'''connections {{
 ovpn-gre {{
  version = 2
  local_addrs = {local}
  remote_addrs = {remote}
  proposals = aes256gcm16-prfsha256-ecp256
  dpd_delay = 20s
  local {{
   auth = psk
   id = {local}
  }}
  remote {{
   auth = psk
   id = {remote}
  }}
  children {{
   gre {{
    local_ts = {local}/32[gre]
    remote_ts = {remote}/32[gre]
    mode = transport
    esp_proposals = aes256gcm16-ecp256
    start_action = trap
    dpd_action = restart
    close_action = start
   }}
  }}
 }}
}}
secrets {{
 ike-ovpn {{
  id-1 = {local}
  id-2 = {remote}
  secret = {psk}
 }}
}}
'''

def deploy(c,ep,psk):
    for p in sorted((ROOT/'payload'/ep.role).rglob('*')):
        if not p.is_file():continue
        path='/'+p.relative_to(ROOT/'payload'/ep.role).as_posix()
        text=render(p.read_text(),c,ep.role)
        executable=text.startswith('#!')
        mode=0o700 if executable else 0o600
        if '/systemd/' in path or '/nginx/' in path:mode=0o644
        if path.endswith(('ovpn-link-server.py','ovpn-acme-proxy.py')):mode=0o755
        ep.write(path,text,mode)
    ep.write('/etc/swanctl/conf.d/ovpn-gre.conf',swan(c,ep.role,psk))
    ep.write('/usr/local/sbin/ovpn-install-rollback',ROLLBACK,0o700)
    ep.write('/var/lib/ovpn-installer/role',ep.role+'\n')

ROLLBACK=r'''#!/usr/bin/python3
import pathlib,json,subprocess,shlex,os,shutil,re
P=pathlib.Path
state=P('/var/lib/ovpn-installer')
def fail(code):
 print('VPNAI_DIAG:'+code,flush=True);raise SystemExit(1)
def call(*a):
 try:return subprocess.run(a,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20 if a[0]=='swanctl' and '--terminate' in a else None).returncode
 except subprocess.TimeoutExpired:return 124
 except FileNotFoundError:fail('CLEAN_TOOLS')
if os.geteuid()!=0:raise SystemExit('Run as root')
try:
 role=(state/'role').read_text().strip();owned=json.loads((state/'owned.json').read_text());baseline=json.loads((state/'baseline.json').read_text())
except (OSError,ValueError):fail('CLEAN_OWNER')
if role not in ('ru','nl'):fail('CLEAN_ROLE')
if any(not shutil.which(name) for name in ('systemctl','ip','iptables','swanctl','sysctl')):fail('CLEAN_TOOLS')
for info in owned.values():
 if info.get('backup') and not P(info['backup']).is_file():fail('CLEAN_BACKUP')
units=['ovpn-acme-proxy','ovpn-tcp-network','ovpn-network'] if role=='nl' else ['ovpn-tcp-network','ovpn-network']
if role=='ru':units=['openvpn-server@ru','openvpn-server@ru-tcp','ovpn-list-update.timer','ovpn-crl-refresh.timer','ovpn-links','ovpn-links-cleanup','ovpn-cert-renew.timer','ovpn-cert-renew']+units
for unit in units:call('systemctl','disable','--now',unit)
call('swanctl','--terminate','--ike','ovpn-gre')
p=P('/usr/local/sbin/ovpn-network')
if p.exists():
 tcp=P('/usr/local/sbin/ovpn-tcp-network')
 for line in reversed((p.read_text()+'\n'+(tcp.read_text() if tcp.exists() else '')).splitlines()):
  if line.startswith('rule '):
   table,chain,*args=shlex.split(line)[1:]
   while call('iptables','-t',table,'-D',chain,*args)==0:pass
if role=='ru':
 call('iptables','-t','mangle','-F','OVPN_CLASSIFY');call('iptables','-t','mangle','-X','OVPN_CLASSIFY')
 if shutil.which('ip6tables'):
  call('ip6tables','-D','FORWARD','-i','tun-ovpn','-j','REJECT');call('ip6tables','-D','FORWARD','-i','tun-ovpn-tcp','-j','REJECT')
 call('ip','rule','del','pref','10310','fwmark','0x310/0xfff','table','310');call('ip','route','flush','table','310')
call('ip','route','flush','dev','gre-nl');call('ip','link','del','gre-nl')
if role=='ru':
 if shutil.which('ipset'):
  for name in ['ovpn_nl','ovpn_force_ru']:call('ipset','destroy',name)
 link=P('/etc/nginx/sites-enabled/ovpn-links')
 if link.is_symlink():link.unlink()
for path,info in reversed(list(owned.items())):
 p=P(path)
 if path.startswith('/var/lib/ovpn-installer') or path in ['/usr/local/sbin/ovpn-install-rollback','/etc/openvpn/server/users.json','/etc/ovpn-routing/source.url','/etc/ovpn-routing/extra-nl.txt','/etc/ovpn-routing/force-ru.txt']:continue
 if p.is_symlink():fail('CLEAN_PATH')
 if info['backup']:
  p.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(P(info['backup']),p)
 else:p.unlink(missing_ok=True)
for key,value in baseline['sysctl'].items():
 if value:call('sysctl','-w',key+'='+value)
call('systemctl','daemon-reload')
# Do not stop an IPsec daemon now serving connections from another installation.
conns=subprocess.run(['swanctl','--list-conns'],capture_output=True,text=True)
foreign=conns.returncode!=0 or any(name!='ovpn-gre' for name in re.findall(r'^([^\s:]+):',conns.stdout,re.M))
if not foreign:call('systemctl','disable','--now','strongswan')
if role=='ru' and shutil.which('nginx') and call('nginx','-t')==0:call('systemctl','reload','nginx')
(state/'rolled-back').write_text('Rollback performed; resume required.\n')
print('Own VPN rules/configs removed. Packages/PKI/users retained for recovery.')
'''


def install_packages(ep):
    pkgs='strongswan-swanctl charon-systemd libstrongswan-standard-plugins libcharon-extra-plugins iproute2 iptables curl ca-certificates openssl'
    if ep.role=='ru':pkgs+=' openvpn easy-rsa ipset nginx python3-venv python3-qrcode'
    ep.shell('set -e\nexport DEBIAN_FRONTEND=noninteractive\napt-get update\napt-get install -y '+pkgs+'\nmodprobe ip_gre\n')

def initialize_ru(c,ru):
    # Personal defaults apply only on a new installation; never overwrite an existing list.
    own_file=ROOT/'own-ru.txt'
    own_text=own_file.read_text() if own_file.exists() else '# Own public IPv4/CIDR via Russian server\n'
    for line in own_text.splitlines():
        entry=line.split('#')[0].strip()
        if entry:
            net=ipaddress.ip_network(entry,strict=False)
            if net.version!=4 or not net.is_global or net.prefixlen<4:raise InstallError('Некорректный адрес в own-ru.txt: '+entry)
    # These are the only data files initialized; existing users/manual CIDRs are preserved.
    for path,text in [('/etc/openvpn/server/users.json','{}'),('/etc/ovpn-routing/source.url',c['source_url']+'\n'),('/etc/ovpn-routing/extra-nl.txt','# Own IPv4/CIDR via NL\n'),('/etc/ovpn-routing/force-ru.txt',own_text)]:ru.write(path,text,preserve=True)
    ru.shell('''set -e
umask 077
install -d -m 700 /root/ovpn-profiles /root/ovpn-downloads
id ovpn-links >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin ovpn-links
install -d -m 750 -o root -g ovpn-links /var/lib/ovpn-links
install -d -m 755 /var/www/ovpn-acme /var/www/ovpn-acme/.well-known /var/www/ovpn-acme/.well-known/acme-challenge
export EASYRSA_PKI=/etc/openvpn/server/pki EASYRSA_BATCH=1 EASYRSA_ALGO=ec EASYRSA_CURVE=prime256v1
if [ ! -f "$EASYRSA_PKI/ca.crt" ]; then
 /usr/share/easy-rsa/easyrsa init-pki
 EASYRSA_REQ_CN=OVPN-RU-CA /usr/share/easy-rsa/easyrsa build-ca nopass
fi
if [ ! -f "$EASYRSA_PKI/issued/ru-server.crt" ]; then /usr/share/easy-rsa/easyrsa build-server-full ru-server nopass; fi
/usr/share/easy-rsa/easyrsa gen-crl
if [ ! -f /etc/openvpn/server/tls-crypt.key ]; then openvpn --genkey tls-crypt /etc/openvpn/server/tls-crypt.key; fi
python3 -m py_compile /usr/local/libexec/ovpn-menu.py /usr/local/sbin/ovpn-user /usr/local/sbin/ovpn-custom /usr/local/sbin/ovpn-link /usr/local/libexec/ovpn-link-server.py
ovpn-routing update
''')

def setup_https(c,ru,nl):
    nl.shell('set -e\nsystemctl enable --now ovpn-acme-proxy.service\n')
    # Repair public ACME traversal even when resuming an installation created with umask 077.
    ru.shell('set -e\ninstall -d -m 755 /var/www/ovpn-acme /var/www/ovpn-acme/.well-known /var/www/ovpn-acme/.well-known/acme-challenge\n')
    # First serve only ACME on port 80. SSL server is installed only after cert issuance.
    initial='''server {
 listen 80;
 server_name %s;
 access_log off;
 location ^~ /.well-known/acme-challenge/ { root /var/www/ovpn-acme; }
 location / { return 404; }
}
'''%c['ru_ip']
    ru.write('/etc/nginx/sites-available/ovpn-links',initial,0o644)
    ru.shell('set -e\nln -sf /etc/nginx/sites-available/ovpn-links /etc/nginx/sites-enabled/ovpn-links\nnginx -t\nsystemctl enable --now nginx\nsystemctl reload nginx\nif ! /opt/ovpn-certbot/bin/certbot --version 2>/dev/null | grep -qx "certbot 5.8.0"; then\n python3 -m venv /opt/ovpn-certbot\n /opt/ovpn-certbot/bin/pip install "certbot==5.8.0"\nfi\n')
    certificate=json.loads(ru.shell('python3 /usr/local/sbin/ovpn-cert-manage.py ensure',quiet=True) or '{}')
    text=(ROOT/'payload/ru/etc/nginx/sites-available/ovpn-links').read_text()
    ru.write('/etc/nginx/sites-available/ovpn-links',render(text,c,'ru'),0o644)
    ru.shell('set -e\nnginx -t\nsystemctl reload nginx\n')
    renewal=json.loads(ru.shell('python3 /usr/local/sbin/ovpn-cert-manage.py probe',quiet=True) or '{}')
    return {'certificate':certificate,'renewal':renewal}

def ensure_ipsec(ru):
    # trap policy can establish CHILD_SA before the explicit initiate command.
    def installed():
        output=ru.shell('swanctl --list-sas',quiet=True)
        return bool(re.search(r'^\s*gre:\s+#\d+[^\n]*\bINSTALLED\b',output,re.M))
    if installed():return
    try:ru.shell('swanctl --initiate --child gre',quiet=True)
    except InstallError:
        # A packet may have triggered establishment between the check and initiate.
        if installed():return
        ru.shell('systemctl status strongswan --no-pager; journalctl -u strongswan -n 60 --no-pager; true')
        raise
    if not installed():raise InstallError('IPsec: команда завершилась, но туннель gre не установлен')


def activate(c,ru,nl):
    for ep in [nl,ru]:
        ep.shell('set -e\nsystemctl daemon-reload\nsystemctl enable --now ovpn-network.service ovpn-tcp-network.service\nsystemctl enable --now strongswan.service\nswanctl --load-all || { systemctl status strongswan --no-pager; journalctl -u strongswan -n 60 --no-pager; exit 1; }\n')
    ensure_ipsec(ru)
    ru.shell('set -e\nsystemctl enable --now openvpn-server@ru.service openvpn-server@ru-tcp.service ovpn-list-update.timer ovpn-crl-refresh.timer ovpn-links.service ovpn-links-cleanup.service ovpn-cert-renew.timer\n')
    if c.get('initial_user'):
        output=ru.python(INITIAL_USER,c['initial_user'])
        return json.loads(output or '{}')
    return {}

INITIAL_USER=r'''import pathlib,subprocess,json
users=json.loads(pathlib.Path('/etc/openvpn/server/users.json').read_text())
record=users.get(DATA)
created=record is None
if created:
 result=subprocess.run(['ovpn-user','add',DATA],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 if result.returncode:print('VPNAI_DIAG:INITIAL_USER');raise SystemExit(1)
else:
 if not record.get('enabled') or record.get('deleted'):
  print('VPNAI_DIAG:INITIAL_USER_DISABLED');raise SystemExit(1)
users=json.loads(pathlib.Path('/etc/openvpn/server/users.json').read_text())
if not users.get(DATA,{}).get('enabled') or users[DATA].get('deleted'):
 print('VPNAI_DIAG:INITIAL_USER');raise SystemExit(1)
print(json.dumps({'name':DATA,'created':created,'active':True}))
'''

DIAGNOSTICS={
 'BACKUP_INVALID':'архив повреждён, изменился, неполон или содержит неподдерживаемые пути; восстановление остановлено',
 'INITIAL_USER':'выбранный пользователь не создан или его UDP/TCP-профили отсутствуют',
 'INITIAL_USER_DISABLED':'выбранный логин отключён или удалён; укажите новый логин либо включите пользователя через меню',
 'CLEAN_OWNER':'не найдены или повреждены данные владельца установки; удаление остановлено',
 'CLEAN_ROLE':'роль сервера не совпадает с сохранённой установкой',
 'CLEAN_PATH':'обнаружена неожиданная ссылка или небезопасный путь; удаление остановлено',
 'CLEAN_BACKUP':'резервная копия отсутствует, повреждена или недоступна',
 'CLEAN_TOOLS':'отсутствует обязательная системная утилита для удаления',
 'HTTPS_NETWORK':'Let’s Encrypt недоступен через NL и напрямую; проверьте туннель и исходящий HTTPS',
 'HTTPS_ISSUE':'не удалось выпустить или обновить HTTPS-сертификат; смотрите журнал Certbot на RU',
 'HTTPS_RATE':'Let’s Encrypt ограничил число запросов; текущий сертификат сохранён, дождитесь разрешённого срока',
 'HTTPS_CHALLENGE':'Let’s Encrypt не подтвердил IP; проверьте доступность HTTP-проверки на RU TCP 80',
 'CLEAN_ROLLBACK':'не удалось завершить откат сетевых настроек; сохранены данные для повторного удаления',
 'NAMESPACE_BUSY':'временная тестовая сеть или интерфейс уже существуют; чужие объекты не удалялись',
 'PROBE_ADDRESS_BUSY':'адрес теста используется клиентом; тест остановлен без отключения клиента',
 'NAMESPACE_SETUP':'не удалось создать временную тестовую сеть или её маршрут',
 'PROBE_RULES':'не удалось применить временные правила теста',
 'NL_EXIT':'тестовый HTTPS-запрос через NL не прошёл',
 'RU_EXIT':'тестовый HTTPS-запрос через RU не прошёл',
 'NL_EXIT_MISMATCH':'тестовый трафик вышел с адреса, отличного от ожидаемого NL',
 'RU_EXIT_MISMATCH':'тестовый трафик вышел с адреса, отличного от ожидаемого RU',
}
VERIFY_UNITS=['ovpn-network','ovpn-tcp-network','strongswan','openvpn-server@ru','openvpn-server@ru-tcp','nginx','ovpn-links','ovpn-links-cleanup','ovpn-list-update.timer','ovpn-cert-renew.timer','ovpn-crl-refresh.timer']

def diagnostic_message(output):
    # Interpret only fixed codes; never copy arbitrary command output into the UI.
    for line in output.splitlines():
        if not line.startswith('VPNAI_DIAG:'):continue
        value=line[len('VPNAI_DIAG:'):]
        if value in DIAGNOSTICS:return DIAGNOSTICS[value]
        if value.startswith('SERVICE:') and value[8:] in VERIFY_UNITS+['ovpn-acme-proxy']:return 'неактивна обязательная служба '+value[8:]
    return ''

def verify(c,ru,nl,write_report=True):
    results={'steps':[]}
    def step(name,ep,fn):
        try:
            value=fn();results['steps'].append({'check':name,'server':ep.role,'passed':True});return value
        except Exception as error:
            # Remote errors already redact payloads. Preserve only our own safe messages.
            detail=str(error) if isinstance(error,InstallError) or type(error).__name__=='UserError' else type(error).__name__
            raise InstallError('Проверка «'+name+'», '+('российский' if ep.role=='ru' else 'зарубежный')+' сервер: '+detail) from None
    for ep in [ru,nl]:
        units=VERIFY_UNITS if ep.role=='ru' else VERIFY_UNITS[:3]+(['ovpn-acme-proxy'] if c.get('https_relay') else [])
        script='set -e\nfor unit in '+' '.join(units)+'; do\n if ! systemctl is-active --quiet "$unit"; then printf "VPNAI_DIAG:SERVICE:%s\\n" "$unit"; exit 1; fi\ndone\n'
        step('Службы',ep,lambda ep=ep,script=script:ep.shell(script,quiet=True))
        step('Состояние IPsec',ep,lambda ep=ep:ep.shell('swanctl --list-sas',quiet=True))
        results[ep.role]={'services':units,'active':True}
    step('Установленный IPsec и защита GRE',ru,lambda:ru.shell('set -e\nswanctl --list-sas 2>/dev/null | grep -q INSTALLED\niptables -C OUTPUT -d '+shlex.quote(c['nl_ip'])+' -p gre -m policy --dir out --pol none -j DROP\n',quiet=True))
    step('Доступность OpenVPN TCP с NL',nl,lambda:nl.python("import socket; s=socket.create_connection((DATA[0],DATA[1]),timeout=10); s.close(); print('OpenVPN TCP port reachable')",[c['ru_ip'],c['ovpn_port']]))
    step('HTTPS: сертификат и ответ сервиса',nl,lambda:nl.python("""import urllib.request,urllib.error
try:urllib.request.urlopen('https://'+DATA+'/',timeout=20)
except urllib.error.HTTPError as e:
 if e.code!=404:raise
else:raise SystemExit('Unexpected public root response')
print('HTTPS verified')
""",c['ru_ip']))
    results['routing_udp_subnet']=step('Выходы RU/NL из подсети UDP',ru,lambda:json.loads(ru.python(PROBE,c)))
    results['routing_tcp_subnet']=json.loads(step('Выходы RU/NL из подсети TCP',ru,lambda:ru.python(PROBE,dict(c,vpn_net=c['tcp_net']))))
    if c.get('routing_mode','full_mixed')=='split':
        code="import pathlib,json; p=pathlib.Path('/var/lib/ovpn-routing/split-status.json'); print(p.read_text() if p.exists() else 'null')"
        status=step('Состояние раздельных маршрутов',ru,lambda:json.loads(ru.python(code)))
        if not isinstance(status,dict) or status.get('default_route') is not False or type(status.get('ipv4_routes')) is not int or status['ipv4_routes']<0:
            raise InstallError('Проверка раздельных маршрутов: split-status.json отсутствует или некорректен. Эта ошибка не означает отказ IPsec; компоненты раздельных маршрутов требуют восстановления.')
        results['split_routes']=status
    else:
        results['split_routes']={'status':'not_applicable','reason':'Фактический режим направляет весь IPv4 через VPN; файл раздельных маршрутов не требуется.'}
    results['limitations']=['OpenVPN Connect на личном устройстве не проверялся.','Перезагрузка VPS автоматически не выполнялась.','Работа OpenVPN через сеть конкретного провайдера не проверялась.']
    if write_report:ru.write('/root/ovpn-install-report.json',json.dumps(results,ensure_ascii=False,indent=2))
    return results

PROBE=r'''import subprocess,time,urllib.request,ipaddress,pathlib
c=DATA
# Use a root-owned, exclusively named namespace; refuse collisions rather than altering another namespace.
ns='ovpn-install-check';host='ovi-host';peer='ovi-peer';net=ipaddress.ip_network(c['vpn_net']);client=str(net[250]);gateway=str(net[249]);destination='1.1.1.1'
stage='NAMESPACE_SETUP'
def fail(code):
 print('VPNAI_DIAG:'+code,flush=True);raise SystemExit(1)
def run(*a,check=True):
 r=subprocess.run(a,check=False,capture_output=True,text=True)
 if check and r.returncode:fail(stage)
 return r
if ns in run('ip','netns','list').stdout or host in run('ip','-o','link').stdout:fail('NAMESPACE_BUSY')
statuses=[pathlib.Path('/run/openvpn-server/ru-status.log'),pathlib.Path('/run/openvpn-server/ru-tcp-status.log')]
if any(status.exists() and any(a in status.read_text() for a in [client+'\t',gateway+'\t']) for status in statuses):fail('PROBE_ADDRESS_BUSY')
added=[]
def rule(*args):
 run('iptables',*args);added.append(args)
try:
 run('ip','netns','add',ns);run('ip','link','add',host,'type','veth','peer','name',peer)
 run('ip','link','set',peer,'netns',ns);run('ip','addr','add',gateway+'/32','dev',host);run('ip','link','set',host,'up')
 run('ip','route','add',client+'/32','dev',host);run('ip','-n',ns,'addr','add',client+'/30','dev',peer);run('ip','-n',ns,'link','set',peer,'up');run('ip','-n',ns,'link','set','lo','up');run('ip','-n',ns,'route','add','default','via',gateway)
 stage='PROBE_RULES'
 # Add only a dedicated match for this probe, then remove it in finally.
 rule('-t','mangle','-I','PREROUTING','1','-i',host,'-s',client+'/32','-j','OVPN_CLASSIFY')
 rule('-I','FORWARD','1','-i',host,'-s',client+'/32','-j','ACCEPT')
 rule('-I','FORWARD','1','-o',host,'-d',client+'/32','-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT')
 stage='NL_EXIT'
 # NL traffic forced with a high-priority exact probe route, without changing any source CIDRs.
 run('ip','rule','add','pref','10309','from',client+'/32','lookup','310')
 try:
  r=run('ip','netns','exec',ns,'curl','-4','-fsS','--max-time','20','https://1.1.1.1/cdn-cgi/trace')
  if 'ip='+c['nl_ip']+'\n' not in r.stdout:fail('NL_EXIT_MISMATCH')
 finally:run('ip','rule','del','pref','10309','from',client+'/32','lookup','310',check=False)
 stage='RU_EXIT'
 # Force fresh probe connections into main; high priority overrides the connmark classifier.
 run('ip','rule','add','pref','10309','from',client+'/32','lookup','main')
 try:
  r=run('ip','netns','exec',ns,'curl','-4','-fsS','--max-time','20','https://1.1.1.1/cdn-cgi/trace')
  if 'ip='+c['ru_ip']+'\n' not in r.stdout:fail('RU_EXIT_MISMATCH')
 finally:run('ip','rule','del','pref','10309','from',client+'/32','lookup','main',check=False)
 print(json.dumps({'nl_exit':c['nl_ip'],'ru_exit':c['ru_ip'],'gre_ipsec_nat':'pass','probe':'isolated namespace, not OpenVPN client handshake'}))
finally:
 for args in reversed(added):
  a=list(args);i=a.index('-I');a[i]='-D'
  if len(a)>i+2 and a[i+2]=='1':a.pop(i+2)
  run('iptables',*a,check=False)
 run('ip','netns','del',ns,check=False);run('ip','link','del',host,check=False)
'''
