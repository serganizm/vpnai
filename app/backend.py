"""Local controller: explicit SSH targets, in-memory credentials and background jobs."""
import ast,base64,contextlib,hashlib,importlib.util,io,ipaddress,json,pathlib,re,secrets,shlex,socket,sys,threading,time,zipfile
ROOT=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('vpn_engine',ROOT/'core/engine.py');engine=importlib.util.module_from_spec(spec);spec.loader.exec_module(engine)
MODES={'split','full_mixed','full_nl'}
AUTH={'password','certificate'}
ACTIONS={'check','install','resume','verify','remove','fresh'}
class UserError(Exception):pass
class Cancelled(UserError):pass

def cidrs(text):
    if not isinstance(text,str) or len(text)>150000:raise UserError('Список слишком большой.')
    result=set()
    for line in text.splitlines():
        value=line.split('#')[0].strip()
        if not value:continue
        try:n=ipaddress.ip_network(value,strict=False)
        except ValueError:raise UserError('Некорректный IP/CIDR: '+value[:60])
        if n.version!=4 or not n.is_global or n.prefixlen<4:raise UserError('Нужен публичный IPv4 или CIDR: '+value[:60])
        result.add(str(n))
    return sorted(result)

def validate(data):
    if not isinstance(data,dict):raise UserError('Ожидается объект настроек.')
    demo=data.get('demo',True)
    if not isinstance(demo,bool):raise UserError('Некорректный режим.')
    clean={'demo':demo,'action':data.get('action','check'),'routing':data.get('routing','split'),'auth':data.get('auth','password')}
    clean['update_packages']=data.get('update_packages',False)
    if not isinstance(clean['update_packages'],bool):raise UserError('Обновление пакетов: выберите Да или Нет.')
    if clean['action'] not in ACTIONS or clean['routing'] not in MODES or clean['auth'] not in AUTH:raise UserError('Неизвестный вариант настройки.')
    clean['ru_routes']=cidrs(data.get('ru_routes',''));clean['eu_routes']=cidrs(data.get('eu_routes',''))
    clean['initial_user']=data.get('initial_user','user1').strip();clean['comment']=data.get('comment','').strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,48}',clean['initial_user']):raise UserError('Логин: латинские буквы, цифры, _ или -, до 48 символов.')
    if len(clean['comment'])>200 or any(ord(c)<32 or ord(c)==127 for c in clean['comment']):raise UserError('Комментарий: до 200 символов, без управляющих знаков.')
    try:clean['vpn_port']=int(data.get('vpn_port',1194))
    except (ValueError,TypeError):raise UserError('Неверный порт OpenVPN.')
    if not 1024<=clean['vpn_port']<=65535 or clean['vpn_port'] in (4500,8765):raise UserError('Выберите порт OpenVPN 1024–65535, кроме 4500 и 8765.')
    clean['scenario']=data.get('scenario','success')
    if clean['scenario'] not in ('success','failure','existing'):raise UserError('Неверный сценарий демонстрации.')
    for role in ('ru','nl'):
        s=data.get(role,{})
        if not isinstance(s,dict):raise UserError('Некорректные данные сервера.')
        host=s.get('host','').strip()
        if demo and not host:host='198.51.100.10' if role=='ru' else '203.0.113.20'
        try:ip=ipaddress.ip_address(host)
        except ValueError:raise UserError('Укажите IPv4 обоих серверов.')
        if ip.version!=4 or (not demo and not ip.is_global):raise UserError('Для установки нужен публичный IPv4.')
        try:port=int(s.get('port',22))
        except (ValueError,TypeError):raise UserError('Некорректный SSH-порт.')
        if not 1<=port<=65535:raise UserError('Некорректный SSH-порт.')
        user=s.get('user','root').strip()
        if user!='root':raise UserError('Эта версия устанавливает VPN под пользователем root.')
        method=s.get('method','password')
        if method not in ('password','key','local-key'):raise UserError('Неизвестный способ SSH-входа.')
        entry={'host':host,'port':port,'user':user,'method':method,'password':s.get('password',''),'key':s.get('key',''),'key_path':s.get('key_path','~/.ssh/id_ed25519'),'passphrase':s.get('passphrase',''),'fingerprint':s.get('fingerprint','')}
        if not all(isinstance(v,str) for k,v in entry.items() if k!='port'):raise UserError('Некорректные данные SSH.')
        if not demo and not entry['password' if method=='password' else 'key_path' if method=='local-key' else 'key']:raise UserError('Введите пароль SSH или содержимое приватного ключа.')
        if len(entry['key'])>65536:raise UserError('Слишком большой SSH-ключ.')
        clean[role]=entry
    if clean['ru']['host']==clean['nl']['host']:raise UserError('У серверов должны быть разные IP.')
    for item in clean['eu_routes']:
        if any(ipaddress.ip_address(clean[r]['host']) in ipaddress.ip_network(item) for r in ('ru','nl')):raise UserError('Список RU-EU не должен включать адреса самих серверов.')
    if clean['action'] in ('remove','fresh') and data.get('confirmation')!='УДАЛИТЬ':raise UserError('Для этого действия введите УДАЛИТЬ.')
    return clean


INSPECT_MODES = r"""import pathlib,json
base=pathlib.Path('/etc/openvpn/server')
profiles=[]
for name in ('ru.conf','ru-tcp.conf'):
 p=base/name
 if not p.exists():profiles.append(None);continue
 lines=[s.strip() for s in p.read_text().splitlines() if s.strip() and not s.lstrip().startswith(('#',';'))]
 profiles.append({'redirect':any(s.startswith('push ') and 'redirect-gateway' in s for s in lines),'split':any(s.startswith('client-connect ') and 'ovpn-split-connect' in s for s in lines),'password':any(s.startswith('auth-user-pass-verify ') for s in lines)})
p=pathlib.Path('/usr/local/sbin/ovpn-network')
network=p.read_text() if p.exists() else ''
print(json.dumps({'profiles':profiles,'list_classifier':'--match-set ovpn_nl' in network,'split_tools':all(pathlib.Path(p).is_file() for p in ('/usr/local/sbin/ovpn-split-routes','/usr/local/libexec/ovpn-split-connect'))}))
"""

def installed_modes(ep,previous,allow_incomplete=False):
    observed=json.loads(ep.python(INSPECT_MODES));profiles=observed['profiles'];saved=previous['config']
    complete=len(profiles)==2 and all(isinstance(p,dict) for p in profiles)
    routing='unknown';auth='unknown'
    if complete:
        if all(p['split'] and not p['redirect'] for p in profiles):routing='split'
        elif all(p['redirect'] and not p['split'] for p in profiles):
            if observed['list_classifier']:routing='full_mixed'
            elif saved.get('routing_mode')=='full_nl':routing='full_nl'
        if all(p['password'] for p in profiles):auth='password'
        elif all(not p['password'] for p in profiles):auth='certificate'
    source='profiles'
    if allow_incomplete and previous.get('version')==2 and previous.get('complete') is False and profiles==[None,None]:
        routing=saved.get('routing_mode');auth=saved.get('auth_mode');source='saved-incomplete'
        if routing not in ('split','full_mixed','full_nl') or auth not in ('password','certificate'):routing=auth='unknown'
    return {'source':source,'routing':routing,'auth':auth,'state_version':previous.get('version'),'legacy':previous.get('version',1)<2,'split_tools':observed['split_tools']}

def get_paramiko():
    try:import paramiko;return paramiko
    except ImportError:
        if getattr(sys,'frozen',False):raise UserError('Встроенный SSH-компонент недоступен. Скачайте целиком самостоятельную сборку VPNAI для вашей ОС; устанавливать Paramiko отдельно не требуется.') from None
        raise UserError('Для реальных серверов установите SSH-компонент: запустите из папки app файл для своей ОС: setup-ssh-windows.bat (Windows), setup-ssh-macos.command (macOS) или setup-ssh-linux.sh (Linux). Перед установкой закройте приложение, после установки запустите его снова.')

def fingerprint(key):return 'SHA256:'+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')

def fingerprints(settings):
    """Read host keys without authenticating or running commands."""
    pm=get_paramiko();result={}
    for role in ('ru','nl'):
        s=settings[role];sock=None;transport=None
        try:
            sock=socket.create_connection((s['host'],s['port']),timeout=8)
            transport=pm.Transport(sock);transport.start_client(timeout=8)
            result[role]=fingerprint(transport.get_remote_server_key())
        except Exception as error:
            raise UserError('Не удалось автоматически получить SSH-ключ: '+('российский' if role=='ru' else 'зарубежный')+' сервер '+s['host']+':'+str(s['port'])+' ('+type(error).__name__+'). Проверьте адрес, порт и доступность. Пароль ещё не передавался.') from None
        finally:
            if transport:transport.close()
            if sock:sock.close()
    return result

class Remote(engine.Endpoint):
    def __init__(self,role,settings):self.role=role;self.settings=settings;self.client=None;self.host=settings['host'];self.guard=None
    def connect(self):
        pm=get_paramiko();expected=self.settings['fingerprint']
        if not expected:raise UserError('Сначала получите и подтвердите SSH-отпечатки.')
        class Pin(pm.MissingHostKeyPolicy):
            def missing_host_key(_self,client,hostname,key):
                if not secrets.compare_digest(fingerprint(key),expected):raise UserError('SSH-отпечаток сервера изменился. Соединение отклонено.')
        client=pm.SSHClient();client.set_missing_host_key_policy(Pin());self.client=client
        s=self.settings;options=dict(hostname=s['host'],port=s['port'],username='root',timeout=10,banner_timeout=12,auth_timeout=15,allow_agent=False,look_for_keys=False)
        if s['method']=='password':options['password']=s['password']
        else:
            key_text=s['key']
            if s['method']=='local-key':
                path=pathlib.Path(s['key_path']).expanduser()
                if not path.is_file() or path.stat().st_size>65536:raise UserError('Локальный приватный ключ не найден или слишком большой. Укажите путь к файлу без .pub.')
                try:key_text=path.read_text()
                except (OSError,UnicodeError):raise UserError('Не удалось прочитать локальный приватный ключ.')
            key=None
            for cls in (pm.Ed25519Key,pm.ECDSAKey,pm.RSAKey):
                try:key=cls.from_private_key(io.StringIO(key_text),password=s['passphrase'] or None);break
                except Exception:continue
            if key is None:raise UserError('Не удалось прочитать приватный SSH-ключ. Проверьте формат и пароль ключа.')
            options['pkey']=key
        try:client.connect(**options)
        except UserError:raise
        except Exception as e:
            server=('российский' if self.role=='ru' else 'зарубежный')+' сервер '+self.host+':'+str(s['port'])
            if isinstance(e,getattr(pm,'AuthenticationException',())):
                raise UserError('SSH: '+server+' отклонил авторизацию ('+('пароль' if s['method']=='password' else 'ключ')+'). Проверьте данные именно этого сервера и разрешённый способ входа. Получение отпечатка не проверяет пароль.') from None
            if isinstance(e,(TimeoutError,socket.timeout)):
                raise UserError('SSH: превышено время подключения или авторизации: '+server+'.') from None
            raise UserError('SSH: не удалось подключиться: '+server+' ('+type(e).__name__+'). Проверьте адрес, порт и доступность сервера.') from None
        client.get_transport().set_keepalive(20)
        self.shell('test "$(id -u)" = 0',quiet=True)
    def execute(self,command,payload='',limit=1800):
        inp,out,err=self.client.exec_command(command,timeout=limit);channel=out.channel
        channel.set_combine_stderr(True)
        # Send in a separate thread so command output cannot deadlock the SSH window.
        send_error=[]
        def send():
            try:inp.write(payload);inp.flush();channel.shutdown_write()
            except Exception as e:send_error.append(e)
        sender=threading.Thread(target=send,daemon=True);sender.start();chunks=[];size=0;deadline=time.monotonic()+limit
        while True:
            while channel.recv_ready():
                chunk=channel.recv(65536);size+=len(chunk)
                if size<=24*1024*1024:chunks.append(chunk)
            if channel.exit_status_ready() and not channel.recv_ready():break
            if time.monotonic()>deadline:channel.close();raise UserError('Превышено время команды на '+self.role+'. Проверьте сервер перед повторным запуском.')
            time.sleep(.03)
        status=channel.recv_exit_status();sender.join(timeout=2)
        if status or send_error:
            detail=engine.diagnostic_message(b''.join(chunks).decode(errors='replace'))
            if detail:raise UserError(('Российский' if self.role=='ru' else 'Зарубежный')+' сервер: '+detail+' (код '+str(status)+').')
            raise UserError('Команда на '+('российском' if self.role=='ru' else 'зарубежном')+' сервере завершилась с ошибкой'+(' (код '+str(status)+')' if status else '')+'. Проверьте журнал systemd/пакетов на сервере. Пароли в журнал приложения не выводятся.')
        return b''.join(chunks).decode(errors='replace')
    def shell(self,script,quiet=False):return self.execute('bash -s',script)
    def python(self,code,data=None):
        wrapper='import json,sys\nDATA=json.load(sys.stdin)\n'+code
        return self.execute('python3 -c '+shlex.quote(wrapper),json.dumps(data))
    def lock(self):
        inp,out,err=self.client.exec_command("flock -n /run/ovpn-installer.lock sh -c 'printf READY; cat >/dev/null'",timeout=10)
        if out.read(5)!=b'READY':raise UserError('На сервере уже выполняется другая установка.')
        self.guard=(inp,out,err)
    def close(self):
        if self.guard:
            with contextlib.suppress(Exception):self.guard[0].channel.close()
        if self.client:self.client.close()
        self.settings.clear()

SYSTEM_INFO='''set -e
. /etc/os-release
printf '%s\\n%s\\n' "$ID" "$VERSION_ID"
if command -v python3 >/dev/null 2>&1; then python3 -c 'import sys; print(".".join(map(str,sys.version_info[:3])))'; else printf 'missing\\n'; fi
'''
APT_ENV='export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a\n'
APT='apt-get -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold '

def system_info(ep):
    lines=ep.shell(SYSTEM_INFO,quiet=True).strip().splitlines()
    if len(lines)!=3:raise UserError('Не удалось определить ОС и Python на сервере '+ep.role+'.')
    distro,version,python=lines
    if not ((distro=='ubuntu' and version in ('24.04','26.04')) or (distro=='debian' and version in ('12','13'))):raise UserError('Поддерживаются Ubuntu 24.04/26.04 и Debian 12/13. Сервер: '+ep.role+'.')
    return {'os':distro,'version':version,'python':python,'python_installed':False,'packages_updated':False,'reboot_required':False}

def ensure_python(ep,info,allow_install):
    if info['python']!='missing':return
    if not allow_install:raise UserError('На сервере '+ep.role+' отсутствует Python 3. Установка и восстановление установят его автоматически; проверка и удаление пакеты не меняют.')
    ep.shell('set -e\n'+APT_ENV+APT+'update\n'+APT+'install -y python3\n')
    refreshed=system_info(ep)
    if refreshed['python']=='missing':raise UserError('Python 3 не появился после установки на '+ep.role+'.')
    info['python']=refreshed['python'];info['python_installed']=True

def update_system(ep,info):
    ep.shell('set -e\n'+APT_ENV+APT+'update\n'+APT+'upgrade -y\n')
    info['packages_updated']=True
    info['python']=system_info(ep)['python']
    info['reboot_required']=ep.shell("if test -f /var/run/reboot-required; then printf yes; else printf no; fi",quiet=True).strip()=='yes'


BASE_RENDER=engine.render

def render(text,c,role):
    s=BASE_RENDER(text,c,role)
    if role!='ru':return s
    if 'server ' in s and 'verify-client-cert require' in s:
        if c['routing_mode']!='split':s=s.replace('client-connect /usr/local/libexec/ovpn-split-connect','push "redirect-gateway def1"')
        if c['auth_mode']=='certificate':s='\n'.join(l for l in s.splitlines() if not l.startswith('auth-user-pass-verify '))+'\n'
    if c['routing_mode']=='full_nl' and 'iptables -t mangle -A OVPN_CLASSIFY' in s:
        s='\n'.join(l for l in s.splitlines() if not ('OVPN_CLASSIFY' in l and '--match-set ovpn_force_ru' in l))+'\n'
        s=s.replace('-m set --match-set ovpn_nl dst ','')
    if s.startswith('#!/usr/bin/python3') and 'def create_profiles(name):' in s and c['auth_mode']=='certificate':
        s=s.replace('auth-user-pass\n','')
        s=s.replace("'\\nPassword: '+password+", "'\\nAuthentication: certificate only'+")
    if 'def password_menu():' in s and c['auth_mode']=='certificate':
        s=s.replace('def password_menu():','def password_menu():\n print(muted("Вход по сертификату: пароль не используется."));pause();return')
    return s
engine.render=render

from removal import CLEAN, PREFLIGHT as CLEAN_PREFLIGHT, BACKUP as CLEAN_BACKUP

def remove_installation(job,c,ru,nl):
    pair={k:c[k] for k in ('ru_ip','nl_ip')};report={};job.report['removal']=report
    endpoints=(nl,ru)
    for ep in endpoints:
        job.checkpoint();role=ep.role
        job.event('Проверка удаления',12,'Проверка данных владельца и готовности: '+('зарубежный' if role=='nl' else 'российский')+' сервер.')
        try:report[role]=json.loads(ep.python(CLEAN_PREFLIGHT,{'role':role,'pair':pair}))
        except UserError as e:raise UserError('Проверка перед удалением: '+str(e)) from None
    # Both backups must finish before any service is stopped on either host.
    for ep in endpoints:
        job.checkpoint();role=ep.role;meta=report[role]
        if meta['already_removed']:continue
        job.event('Резервная копия',15,'Создание закрытого архива перед удалением: '+('зарубежный' if role=='nl' else 'российский')+' сервер.')
        try:meta['backup']=json.loads(ep.python(CLEAN_BACKUP,{'role':role,'pair':pair}))['backup']
        except UserError as e:raise UserError('Резервное копирование перед удалением: '+str(e)) from None
    for index,ep in enumerate(endpoints):
        job.checkpoint();role=ep.role;meta=report[role]
        if meta['already_removed'] and not meta.get('finalize'):meta['complete']=True;continue
        job.event('Удаление',25+index*30,'Удаление компонентов своей установки: '+('зарубежный' if role=='nl' else 'российский')+' сервер.')
        try:ep.python(CLEAN,{'role':role,'pair':pair,'backup':meta['backup'],'rollback':engine.ROLLBACK})
        except UserError as e:raise UserError('Удаление: '+str(e)+' Уже завершённые этапы указаны в отчёте; повторный запуск учитывает частичное удаление.') from None
        meta['complete']=True


class Job:
    def __init__(self,settings):
        self.id=secrets.token_urlsafe(18);self.demo=settings['demo'];self.settings=settings;self.cancel=threading.Event();self.lock=threading.RLock();self.status='running';self.phase='Подготовка';self.progress=0;self.events=[];self.report={'demo':self.demo,'action':settings['action'],'routing':settings['routing'],'auth':settings['auth'],'update_packages':settings['update_packages'],'servers':{r:settings[r]['host'] for r in ('ru','nl')},'initial_user':settings['initial_user'],'lists':{'ru':settings['ru_routes'],'eu':settings['eu_routes']}};self.artifact=None;self.expires=0
    def event(self,phase,progress,message):
        with self.lock:self.phase=phase;self.progress=progress;self.events.append({'time':time.strftime('%H:%M:%S'),'message':message})
    def checkpoint(self):
        if self.cancel.is_set():raise Cancelled('Операция остановлена между этапами.')
    def public(self):
        with self.lock:return {'id':self.id,'status':self.status,'phase':self.phase,'progress':self.progress,'events':list(self.events),'report':self.report,'download':bool(self.artifact and time.time()<self.expires),'demo':self.demo}
    def run(self):
        try:
            if self.settings['demo']:demo_run(self)
            else:real_run(self)
            with self.lock:self.status='success';self.progress=100
        except Cancelled as e:
            self.event('Остановлено',self.progress,str(e));self.status='cancelled'
        except Exception as e:
            message=str(e) if isinstance(e,(UserError,engine.InstallError)) else 'Операция не завершена ('+type(e).__name__+'). Проверьте соединение и повторите проверку серверов.'
            self.event('Ошибка',self.progress,message);self.status='error'
        finally:
            self.settings.clear()

def demo_run(job):
    s=job.settings;job.report={'demo':True,'action':s['action'],'routing':s['routing'],'auth':s['auth'],'update_packages':s['update_packages'],'initial_user':s['initial_user'],'servers':{'ru':s['ru']['host'],'nl':s['nl']['host']},'lists':{'ru':s['ru_routes'],'eu':s['eu_routes']},'notice':'Это симуляция. SSH-соединения не создавались, файлы на серверах не менялись.'}
    steps=[('Проверка серверов','Показан пример проверки Ubuntu, SSH и свободных портов.'),('Проверка установки','Найдена демонстрационная установка.' if s['scenario']=='existing' else 'Пример: серверы готовы к новой установке.'),('Подготовка файлов','Режимы и ручные списки собраны из формы.'),('Установка компонентов','Имитация проверки/установки Python 3 и VPN-пакетов. '+('Общее обновление ОС включено.' if s['update_packages'] else 'Общее обновление ОС пропущено по выбору.')),('Настройка туннеля','Имитация проверки защищённого канала между серверами.'),('OpenVPN UDP и TCP','Имитация запуска двух служб.'),('Проверка маршрутов','Имитация проверки выбранных выходов.'),('Результат','Демонстрация завершена. Реальный VPN не устанавливался.')]
    if s['action']=='check':steps=steps[:2]+[steps[-1]]
    elif s['action']=='verify':steps=steps[:2]+steps[-2:]
    elif s['action']=='remove':steps=steps[:2]+[('Удаление','Имитация резервного копирования и удаления своей установки.'),steps[-1]]
    for i,(phase,msg) in enumerate(steps):
        job.checkpoint();job.event(phase,int(i/len(steps)*95),msg)
        if s['scenario']=='existing' and s['action']=='install' and i==1:raise UserError('Найдена демонстрационная установка. Выберите восстановление или установку заново.')
        for _ in range(8):
            if job.cancel.wait(.09):job.checkpoint()
        if s['scenario']=='failure' and i==len(steps)//2:raise UserError('Демонстрационная ошибка: выбран пример недоступного сервера. Настоящих подключений не было.')
    if s['action'] not in ('check','remove'):
        buffer=io.BytesIO()
        with zipfile.ZipFile(buffer,'w',zipfile.ZIP_DEFLATED) as z:
            z.writestr('DEMO-README.txt','Демонстрационный архив. Здесь нет действующих сертификатов, ключей или VPN-профилей.\n')
            z.writestr('plan.json',json.dumps(job.report,ensure_ascii=False,indent=2))
        job.artifact=buffer.getvalue();job.expires=time.time()+600

def config(s):
    return {'ru_ip':s['ru']['host'],'nl_ip':s['nl']['host'],'nl_host':'root@'+s['nl']['host'],'ssh_port':s['nl']['port'],'ssh_key':None,'initial_user':s['initial_user'],'vpn_net':'10.77.0.0/24','tcp_net':'10.79.0.0/24','gre_net':'10.78.0.0/30','ovpn_port':s['vpn_port'],'source_url':'https://iplist.opencck.org/?format=json&data=cidr4','routing_mode':s['routing'],'auth_mode':s['auth']}

def collect(ru):
    # ZIP is generated on the host under the shared user lock, then transferred over SSH.
    code=r'''import pathlib,io,zipfile,base64,fcntl,re
with open('/run/ovpn-user.lock','a') as lock:
 fcntl.flock(lock,fcntl.LOCK_SH)
 users=json.loads(pathlib.Path('/etc/openvpn/server/users.json').read_text());buffer=io.BytesIO()
 with zipfile.ZipFile(buffer,'w',zipfile.ZIP_DEFLATED) as archive:
  for name,record in users.items():
   if not record.get('enabled') or record.get('deleted') or not re.fullmatch('[A-Za-z0-9_-]{1,48}',name):continue
   for suffix in ['-UDP.ovpn','-TCP.ovpn','-credentials.txt']:
    p=pathlib.Path('/root/ovpn-profiles')/(name+suffix)
    if p.is_file():archive.writestr(p.name,p.read_bytes())
 print(base64.b64encode(buffer.getvalue()).decode())
'''
    return base64.b64decode(ru.python(code))

def real_run(job):
    s=job.settings;c=config(s);engine.validate(c)
    endpoints=[Remote('ru',dict(s['ru'])),Remote('nl',dict(s['nl']))];ru,nl=endpoints;mutated=False;previous=None
    try:
        job.event('SSH',3,'Подключение к двум указанным серверам с проверкой отпечатков.')
        for ep in endpoints:job.checkpoint();ep.connect()
        for ep in endpoints:ep.lock()
        job.event('ОС и Python',5,'Определение ОС и наличия Python 3 на обоих серверах.')
        system={ep.role:system_info(ep) for ep in endpoints}
        job.report['system']=system
        if s['action']=='check' and any(info['python']=='missing' for info in system.values()):
            job.report['full_check']=False
            job.report['notice']='SSH и ОС проверены. Python 3 отсутствует; полная проверка не выполнена. Выберите установку или восстановление для автоматической установки Python.'
            job.event('Нужен Python 3',100,job.report['notice']);return
        for ep in endpoints:
            job.checkpoint()
            if system[ep.role]['python']=='missing':job.event('Установка Python 3',6,'Установка Python 3: '+('российский' if ep.role=='ru' else 'зарубежный')+' сервер.')
            ensure_python(ep,system[ep.role],s['action'] in ('install','resume','fresh'))
        job.event('Проверка серверов',8,'Проверка адресов, служб и предыдущей установки.')
        inv={ep.role:ep.inventory() for ep in endpoints}
        previous=json.loads(ru.python("import pathlib; p=pathlib.Path('/var/lib/ovpn-installer/state.json'); print(p.read_text() if p.exists() else 'null')"))
        job.report={'demo':False,'action':s['action'],'servers':{r:s[r]['host'] for r in ('ru','nl')},'existing':{r:inv[r]['managed'] for r in ('ru','nl')},'os':{r:inv[r]['os'] for r in ('ru','nl')},'routing':s['routing'],'auth':s['auth'],'update_packages':s['update_packages'],'initial_user':s['initial_user'],'lists':{'ru':s['ru_routes'],'eu':s['eu_routes']},'system':system,'checks':[]}
        if previous and any(previous['config'].get(k)!=c[k] for k in ('ru_ip','nl_ip')):raise UserError('Сохранённая установка относится к другой паре серверов.')
        detected=None
        if previous and s['action'] in ('check','verify','resume'):
            job.event('Режим сервера',9,'Чтение фактических настроек OpenVPN: выбранный в форме режим не применяется при проверке.')
            detected=installed_modes(ru,previous,allow_incomplete=s['action']=='resume')
            job.report['installed']=detected;job.report['requested_routing']=s['routing'];job.report['requested_auth']=s['auth']
            job.report['routing']=detected['routing'];job.report['auth']=detected['auth'];job.report['lists_from_server']=True
            warnings=[]
            if detected.get('source')=='saved-incomplete':warnings.append('Восстановление незавершённой установки использует сохранённые режимы: профили были убраны автоматическим откатом.')
            if detected['legacy']:warnings.append('Обнаружена старая установка; проверка учитывает её формат без изменения серверов.')
            if detected['routing']!=s['routing']:warnings.append('Фактическая маршрутизация: '+{'full_mixed':'весь IPv4 через VPN с выбором RU/NL','full_nl':'весь IPv4 через зарубежный сервер','split':'раздельные маршруты','unknown':'не удалось однозначно определить'}[detected['routing']]+'. Выбор в форме при проверке её не меняет.')
            if detected['auth']!=s['auth']:warnings.append('Авторизация в отчёте взята из действующих настроек сервера.')
            job.report['warnings']=warnings
            for warning in warnings:job.event('Режим сервера',10,warning)
        if s['action']=='check':
            for ep in endpoints:
                class ReadOnly:
                    role=ep.role
                    python=ep.python
                    def write(self,*args,**kwargs):pass
                engine.preflight(c,ReadOnly(),inv[ep.role],bool(previous))
            job.report['details']={r:{'ipsec':inv[r]['swan'],'reserved_files':inv[r]['reserved_files']} for r in ('ru','nl')}
            job.event('Проверка завершена',100,'Доступ и состояние прочитаны. Настройки не менялись.');return
        if s['action'] in ('fresh','remove'):
            remove_installation(job,c,ru,nl)
            previous=None
            if s['action']=='remove':job.event('Удалено',100,'Компоненты этой установки удалены. Другие службы сохранены.');return
            inv={ep.role:ep.inventory() for ep in endpoints}
        if s['action'] in ('resume','verify') and not previous:raise UserError('Сохранённая установка не найдена. Выберите установку после проверки серверов.')
        if s['action']=='install' and (previous or any(inv[r]['managed'] for r in ('ru','nl'))):raise UserError('Найдена предыдущая установка. Выберите восстановление или установку заново.')
        if previous:
            saved=dict(previous['config'])
            if detected:
                if detected['routing']=='unknown' or detected['auth']=='unknown':raise UserError('Режимы двух OpenVPN-служб не удалось однозначно определить. Серверы не изменены; проверьте конфигурации перед восстановлением.')
                saved['routing_mode']=detected['routing'];saved['auth_mode']=detected['auth']
            if s['action']=='resume' and (saved.get('routing_mode','split')!=c['routing_mode'] or saved.get('auth_mode','password')!=c['auth_mode']):raise UserError('Восстановление сохраняет режим маршрутизации и авторизации. Выберите сохранённые режимы либо установку заново.')
            c=dict(saved);c.setdefault('routing_mode','split');c.setdefault('auth_mode','password')
            job.report['routing']=c['routing_mode'];job.report['auth']=c['auth_mode']
        if s['action']=='verify':
            job.event('Проверка VPN',45,'Проверка служб, HTTPS и реальных выходов из серверных тестовых сетей.')
            job.report['verification']=engine.verify(c,ru,nl,write_report=False);job.report['notice']='Проверка серверов завершена. '+(' '.join(job.report.get('warnings',[]))+' ' if job.report.get('warnings') else '')+'Клиент OpenVPN на личном устройстве не проверялся.'
            job.event('Архив профилей',96,'Проверки VPN пройдены. Чтение существующих профилей для скачивания.')
            try:job.artifact=collect(ru)
            except UserError:raise UserError('Проверки VPN пройдены, но получить архив существующих профилей не удалось. Проверьте /root/ovpn-profiles/ на российском сервере.') from None
            job.expires=time.time()+600;return
        for ep in endpoints:job.checkpoint();engine.preflight(c,ep,inv[ep.role],bool(previous))
        c['https_relay']=True
        state=previous or {'version':2,'config':c,'psk':secrets.token_hex(32),'complete':False}
        state['version']=2;state['complete']=False;state['config']=c
        ru.write('/var/lib/ovpn-installer/state.json',json.dumps(state));mutated=True
        for ep in (nl,ru):
            job.checkpoint()
            if s['update_packages']:
                job.event('Обновление ОС',18 if ep.role=='nl' else 29,'Обновление индекса и установленных пакетов: '+('российский' if ep.role=='ru' else 'зарубежный')+' сервер. Перезагрузка не выполняется.')
                update_system(ep,system[ep.role])
            else:
                job.event('Обновление ОС',18 if ep.role=='nl' else 29,'Общее обновление пакетов пропущено по вашему выбору: '+('российский' if ep.role=='ru' else 'зарубежный')+' сервер.')
                system[ep.role]['reboot_required']=ep.shell("if test -f /var/run/reboot-required; then printf yes; else printf no; fi",quiet=True).strip()=='yes'
            job.checkpoint();job.event('Установка компонентов',22 if ep.role=='nl' else 35,'Установка пакетов и файлов: '+('зарубежный' if ep.role=='nl' else 'российский')+' сервер.')
            engine.install_packages(ep);engine.deploy(c,ep,state['psk'])
        job.checkpoint();job.event('Пользователи и списки',46,'Создание PKI и файлов списков. Личные адреса из прежних проектов не используются.')
        # Preserve existing lists on resume. Fresh installations receive only user-entered addresses.
        ru.write('/etc/ovpn-routing/force-ru.txt','\n'.join(s['ru_routes'])+'\n',preserve=True)
        ru.write('/etc/ovpn-routing/extra-nl.txt','\n'.join(s['eu_routes'])+'\n',preserve=True)
        engine.initialize_ru(c,ru)
        for ep in (nl,ru):
            job.checkpoint();ep.shell('set -e\nsystemctl daemon-reload\nsystemctl enable --now ovpn-network ovpn-tcp-network strongswan\nsystemctl restart strongswan\nswanctl --load-all\n')
        job.checkpoint();job.event('HTTPS',60,'Проверка HTTPS-сертификата; выпуск и продление через защищённый канал NL. HTTP-проверка доступна на RU TCP 80.')
        job.report['https']=engine.setup_https(c,ru,nl)
        if job.report['https'].get('renewal',{}).get('available') is False:
            warning='Рабочий сертификат сохранён, но Let’s Encrypt сейчас недоступен. Автопродление повторит проверку каждый час; проверьте журнал ovpn-cert-renew.'
            job.report.setdefault('warnings',[]).append(warning);job.event('Предупреждение HTTPS',65,warning)
        job.checkpoint();job.event('Запуск VPN',75,'Защищённый туннель и OpenVPN UDP/TCP.')
        engine.activate(c,ru,nl)
        # Apply comment and regenerate all profiles according to the selected auth mode.
        ru.python(r'''import pathlib,subprocess,fcntl
with open('/run/ovpn-user.lock','a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 p=pathlib.Path('/etc/openvpn/server/users.json');users=json.loads(p.read_text())
 if DATA['name'] in users and not DATA['preserve']:users[DATA['name']]['comment']=DATA['comment'];p.write_text(json.dumps(users,ensure_ascii=False,indent=2))
for name,record in users.items():
 if record.get('enabled') and not record.get('deleted'):subprocess.run(['ovpn-user','profiles',name],check=True,stdout=subprocess.DEVNULL)
''',{'name':s['initial_user'],'comment':s['comment'],'preserve':bool(previous)})
        ru.shell('set -e\nsystemctl restart openvpn-server@ru openvpn-server@ru-tcp\n')
        job.checkpoint();job.event('Проверка VPN',88,'Проверка служб, HTTPS и двух выходов через изолированные тестовые сети.')
        job.report['verification']=engine.verify(c,ru,nl)
        job.artifact=collect(ru);job.expires=time.time()+600
        for ep in endpoints:ep.python("import pathlib;pathlib.Path('/var/lib/ovpn-installer/rolled-back').unlink(missing_ok=True)")
        state['complete']=True;ru.write('/var/lib/ovpn-installer/state.json',json.dumps(state))
        job.report['notice']='Серверные проверки завершены. Дополнительно импортируйте профиль и проверьте VPN со своего устройства.'
        if any(info['reboot_required'] for info in system.values()):job.report['notice']+=' Обновления ОС требуют перезагрузки: '+', '.join('российский сервер' if r=='ru' else 'зарубежный сервер' for r,info in system.items() if info['reboot_required'])+'. Она автоматически не выполнялась.'
        job.event('Готово',100,'Установка завершена. Профили доступны для скачивания 10 минут; меню на сервере: /root/menu.sh.')
    except BaseException:
        if mutated:
            job.event('Откат',job.progress,'Возврат настроек этой незавершённой установки. Пользователи и ключи сохраняются для восстановления.')
            for ep in endpoints:
                try:ep.shell('test ! -x /usr/local/sbin/ovpn-install-rollback || /usr/local/sbin/ovpn-install-rollback',quiet=True)
                except Exception:job.event('Откат',job.progress,'Автоматический откат не завершился на '+ep.role+'. Проверьте сервер вручную.')
        raise
    finally:
        for ep in endpoints:ep.close()

def ssh_copy_command(host,port,platform,key_path='~/.ssh/id_ed25519'):
    """Generate commands only. Never execute or read the key here."""
    if not isinstance(host,str):raise UserError('Укажите IPv4 сервера.')
    try:
        ip=ipaddress.ip_address(host.strip());port=int(port)
    except (ValueError,TypeError):raise UserError('Укажите корректные IP и SSH-порт.')
    if ip.version!=4 or not 1<=port<=65535:raise UserError('Укажите корректные IP и SSH-порт.')
    if platform not in ('macos','linux','windows'):raise UserError('Выберите macOS, Linux или Windows.')
    if not isinstance(key_path,str) or not key_path or len(key_path)>4096 or any(ord(c)<32 or ord(c)==127 for c in key_path) or key_path.endswith('.pub'):raise UserError('Укажите путь к приватному ключу без .pub.')
    target='root@'+str(ip)
    remote='set -e; umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; echo >> ~/.ssh/authorized_keys; cat >> ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys'
    if platform=='windows':
        if key_path=='~/.ssh/id_ed25519':pub='"$HOME\\.ssh\\id_ed25519.pub"'
        elif key_path.startswith('~/') or key_path.startswith('~\\'):pub="(Join-Path $HOME '"+(key_path[2:]+'.pub').replace('/', '\\').replace("'","''")+"')"
        else:pub="'"+(key_path+'.pub').replace("'","''")+"'"
        command='Get-Content -ErrorAction Stop -LiteralPath '+pub+' | ssh -p '+str(port)+' '+target+" '"+remote+"'"
        shell='PowerShell';fallback=''
    else:
        if key_path=='~/.ssh/id_ed25519':pub='~/.ssh/id_ed25519.pub'
        elif key_path.startswith('~/'):pub='"$HOME"/'+shlex.quote(key_path[2:]+'.pub')
        else:pub=shlex.quote(key_path+'.pub')
        command='ssh-copy-id -i '+pub+' -p '+str(port)+' '+target
        shell='Терминал';fallback='cat '+pub+' | ssh -p '+str(port)+' '+target+' '+shlex.quote(remote)
    return {'platform':platform,'shell':shell,'command':command,'fallback':fallback}
