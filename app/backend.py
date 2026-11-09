"""Local controller: explicit SSH targets, in-memory credentials and background jobs."""
import ssh_guard
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
    if data.get('demo',False) is not False:raise UserError('Доступна только работа с реальными серверами.')
    demo=False
    clean={'demo':False,'action':data.get('action','check'),'routing':data.get('routing','split'),'auth':data.get('auth','password')}
    import limits_backend
    clean['connection_limit']=limits_backend.validate(data['connection_limit']) if data.get('connection_limit') is not None else None
    clean['dns']=None
    if data.get('dns') is not None:
        import dns_backend
        clean['dns']=dns_backend.validate(data['dns'])
    clean['update_packages']=data.get('update_packages',False)
    if not isinstance(clean['update_packages'],bool):raise UserError('Обновление пакетов: выберите Да или Нет.')
    if clean['action'] not in ACTIONS or clean['routing'] not in MODES or clean['auth'] not in AUTH:raise UserError('Неизвестный вариант настройки.')
    clean['ru_routes']=cidrs(data.get('ru_routes',''));clean['eu_routes']=cidrs(data.get('eu_routes',''))
    clean['initial_user']=data.get('initial_user','user1').strip();clean['comment']=data.get('comment','').strip()
    eu_ssh=data.get('eu_ssh','direct');eu_target=data.get('eu_target','public')
    if eu_ssh not in ('direct','via_ru'):raise UserError('SSH к EU: выберите «напрямую» или «через RU».')
    if eu_target not in ('public','gre'):raise UserError('Цель SSH к EU: публичный IP или GRE.')
    if eu_ssh=='direct':eu_target='public'
    clean['eu_ssh']=eu_ssh;clean['eu_target']=eu_target
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,48}',clean['initial_user']):raise UserError('Логин: латинские буквы, цифры, _ или -, до 48 символов.')
    if len(clean['comment'])>200 or any(ord(c)<32 or ord(c)==127 for c in clean['comment']):raise UserError('Комментарий: до 200 символов, без управляющих знаков.')
    try:clean['vpn_port']=int(data.get('vpn_port',1194))
    except (ValueError,TypeError):raise UserError('Неверный порт OpenVPN.')
    if not 1024<=clean['vpn_port']<=65535 or clean['vpn_port'] in (4500,8765):raise UserError('Выберите порт OpenVPN 1024–65535, кроме 4500 и 8765.')
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
    backup=data.get('restore_backup','')
    if not isinstance(backup,str) or (backup and not re.fullmatch(r'ovpn-backup-[0-9]{8}-[0-9]{6}-[a-f0-9]{12}\.tar\.gz',backup)):raise UserError('Некорректное имя резервного архива.')
    if backup and clean['action']!='resume':raise UserError('Выбор архива доступен только для восстановления.')
    revision=data.get('update_revision','')
    if not isinstance(revision,str) or (revision and not re.fullmatch(r'[a-f0-9]{64}',revision)):raise UserError('Некорректная версия текущей конфигурации.')
    clean['legacy_confirmed']=data.get('legacy_confirmed') is True
    clean['update_revision']=revision
    clean['restore_backup']=backup
    if (clean['action'] in ('remove','fresh') or backup) and data.get('confirmed') is not True:raise UserError('Подтвердите выбранное удаление флажком «Я подтверждаю».')
    return clean


def session_payload(data):
    if not isinstance(data,dict):raise UserError('Некорректные данные текущего сеанса.')
    result={}
    fields=('connection_limit','action','routing','auth','initial_user','comment','vpn_port','update_packages','ru_routes','eu_routes','update_revision','update_user_count','update_loaded_pair','update_legacy','update_dirty','eu_ssh','eu_target')
    server_fields=('host','port','user','method','password','key','key_path','passphrase','alias')
    def copy_value(value):
        if isinstance(value,str) and len(value)<=150000:return value
        if type(value) in (int,bool):return value
        raise UserError('Некорректное поле текущего сеанса.')
    if data.get('dns') is not None:
        import dns_backend
        result['dns']=dns_backend.validate(data['dns'])
    for key in fields:
        if key in data:result[key]=copy_value(data[key])
    for role in ('ru','nl'):
        if role not in data:continue
        if not isinstance(data[role],dict):raise UserError('Некорректные данные сервера.')
        result[role]={key:copy_value(value) for key,value in data[role].items() if key in server_fields}
    return result


UPDATE_READ=r"""import pathlib,json,fcntl,contextlib
# VPNAI_UPDATE_SNAPSHOT
p=pathlib.Path('/var/lib/ovpn-installer/state.json')
state=json.loads(p.read_text()) if p.is_file() else None
base=pathlib.Path('/etc/ovpn-routing')
with (open('/run/ovpn-user.lock','r') if pathlib.Path('/run/ovpn-user.lock').exists() else contextlib.nullcontext()) as lock:
 if lock:fcntl.flock(lock,fcntl.LOCK_SH)
 db=pathlib.Path('/etc/openvpn/server/users.json')
 users=json.loads(db.read_text()) if db.is_file() else {}
 public=[{'name':n,'enabled':bool(v.get('enabled'))} for n,v in sorted(users.items()) if not v.get('deleted')]
config=state.get('config',{}) if state else {}
limits=pathlib.Path('/etc/openvpn/server/connection-limits.json')
print(json.dumps({'connection_limits':limits.read_text() if limits.exists() else None,'config':{k:config.get(k) for k in ('ru_ip','nl_ip','vpn_net','tcp_net','gre_net','ovpn_port','routing_mode','auth_mode')},'users':public,'ru_routes':(base/'force-ru.txt').read_text() if (base/'force-ru.txt').exists() else '', 'eu_routes':(base/'extra-nl.txt').read_text() if (base/'extra-nl.txt').exists() else '', 'state':bool(state)}))
"""

def update_configuration(ru,settings,previous):
    if previous is None:
        import legacy_update
        return legacy_update.read(ru,settings)
    raw=json.loads(ru.python(UPDATE_READ))
    if not raw.get('state'):raise UserError('Сохранённая конфигурация не найдена. Выберите установку или восстановление из архива.')
    if any(raw['config'].get(k)!=settings[role]['host'] for k,role in (('ru_ip','ru'),('nl_ip','nl'))):raise UserError('Конфигурация относится к другой паре серверов.')
    actual=installed_modes(ru,previous,allow_incomplete=True)
    if actual['routing'] not in MODES or actual['auth'] not in AUTH:raise UserError('Не удалось определить текущие режимы. Проверьте конфигурацию сервера.')
    raw['config']['routing_mode']=actual['routing'];raw['config']['auth_mode']=actual['auth']
    raw['ru_routes']=cidrs(raw['ru_routes']);raw['eu_routes']=cidrs(raw['eu_routes'])
    revision=hashlib.sha256(json.dumps(raw,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return dict(raw,revision=revision,user_count=len(raw['users']),active_user_count=sum(u['enabled'] for u in raw['users']))

def read_update_configuration(settings):
    ru=Remote('ru',dict(settings['ru']))
    try:
        ru.connect()
        previous=json.loads(ru.python("import pathlib; p=pathlib.Path('/var/lib/ovpn-installer/state.json'); print(p.read_text() if p.is_file() else 'null')"))
        result=update_configuration(ru,settings,previous)
        import dns_backend
        try:result['dns']=dns_backend.execute(ru,'read')
        except UserError as error:result['dns_error']=str(error)
        import limits_backend
        try:result['limits']=limits_backend.execute(ru,'read')
        except UserError as error:result['limits_error']=str(error)
        return result
    finally:ru.close()

def backup_update(job,c,ru,nl):
    import backups
    pair={k:c[k] for k in ('ru_ip','nl_ip')};snapshot=backups.snapshot(pair,'before-update');saved={}
    for ep in (ru,nl):
        job.checkpoint();saved[ep.role]=json.loads(ep.python(CLEAN_BACKUP,{'role':ep.role,'pair':pair,'snapshot':snapshot,'force_snapshot':True}))['backup']
    job.report['update_backups']=saved
    return saved

UPDATE_PASSWORDS=r"""import pathlib,json,hashlib,hmac,subprocess,fcntl
# Existing certificates and valid passwords are preserved; certificate-only accounts may lack a saved password.
generated=[]
with open('/run/ovpn-user.lock','a') as lock:
 fcntl.flock(lock,fcntl.LOCK_SH)
 users=json.loads(pathlib.Path('/etc/openvpn/server/users.json').read_text())
 candidates=[]
 for name,record in users.items():
  if not record.get('enabled') or record.get('deleted'):continue
  file=pathlib.Path('/root/ovpn-profiles')/(name+'-credentials.txt')
  password=next((line[10:] for line in file.read_text().splitlines() if line.startswith('Password: ')),None) if file.is_file() else None
  try:valid=password is not None and hmac.compare_digest(hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(record['salt']),300000).hex(),record['hash'])
  except (KeyError,ValueError):valid=False
  if not valid:candidates.append(name)
for name in candidates:
 result=subprocess.run(['/usr/local/sbin/ovpn-user','passwd',name,'--auto'],capture_output=True,text=True)
 if result.returncode:raise SystemExit('Не удалось подготовить пароль существующего пользователя.')
 generated.append(name)
print(json.dumps({'generated':generated}))
"""


INSPECT_MODES = r"""import pathlib,json
base=pathlib.Path('/etc/openvpn/server')
profiles=[]
for name in ('ru.conf','ru-tcp.conf'):
 p=base/name
 if not p.exists():profiles.append(None);continue
 lines=[s.strip() for s in p.read_text().splitlines() if s.strip() and not s.lstrip().startswith(('#',';'))]
 profiles.append({'redirect':any(s.startswith('push ') and 'redirect-gateway' in s for s in lines),'split':any(s.startswith('client-connect ') and ('ovpn-split-connect' in s or s.rstrip(chr(34)+chr(39)).endswith('ovpn-session-limit connect')) for s in lines),'password':any(s.startswith('auth-user-pass-verify ') for s in lines)})
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

GRE_EU_HOST='10.78.0.2'

def eu_connect_target(settings):
    """TCP target for EU when jumping via RU: public IP or GRE peer."""
    nl=settings['nl']
    if settings.get('eu_ssh')=='via_ru' and settings.get('eu_target')=='gre':
        return GRE_EU_HOST,nl['port']
    return nl['host'],nl['port']

def make_remote(role,settings):
    """Build Remote; for EU with eu_ssh=via_ru open SSH through authenticated RU jump."""
    if role!='nl' or settings.get('eu_ssh')!='via_ru':
        return Remote(role,dict(settings[role]))
    host,port=eu_connect_target(settings)
    return Remote('nl',dict(settings['nl']),jump=dict(settings['ru']),connect_host=host,connect_port=port)

def _auth_options(pm,settings):
    options=dict(hostname=settings['host'],port=settings['port'],username='root',timeout=10,banner_timeout=12,auth_timeout=15,allow_agent=False,look_for_keys=False)
    if settings['method']=='password':options['password']=settings['password'];return options
    key_text=settings['key']
    if settings['method']=='local-key':
        path=pathlib.Path(settings['key_path']).expanduser()
        if not path.is_file() or path.stat().st_size>65536:raise UserError('Локальный приватный ключ не найден или слишком большой. Укажите путь к файлу без .pub.')
        try:key_text=path.read_text()
        except (OSError,UnicodeError):raise UserError('Не удалось прочитать локальный приватный ключ.')
    key=None
    for cls in (pm.Ed25519Key,pm.ECDSAKey,pm.RSAKey):
        try:key=cls.from_private_key(io.StringIO(key_text),password=settings['passphrase'] or None);break
        except Exception:continue
    if key is None:raise UserError('Не удалось прочитать приватный SSH-ключ. Проверьте формат и пароль ключа.')
    options['pkey']=key;return options

def _open_eu_channel(settings):
    """Authenticate to RU, then open a direct-tcpip channel to the EU SSH target."""
    pm=get_paramiko();ru=settings['ru'];host,port=eu_connect_target(settings)
    if not ru.get('fingerprint'):raise UserError('Сначала получите и подтвердите SSH-отпечатки.')
    class Pin(pm.MissingHostKeyPolicy):
        def missing_host_key(_self,client,hostname,key):
            if not secrets.compare_digest(fingerprint(key),ru['fingerprint']):raise UserError('SSH-отпечаток сервера изменился. Соединение отклонено.')
    jump=pm.SSHClient();jump.set_missing_host_key_policy(Pin())
    try:
        jump.connect(**_auth_options(pm,ru))
        jump.get_transport().set_keepalive(20)
        channel=jump.get_transport().open_channel('direct-tcpip',(host,port),('127.0.0.1',0),timeout=12)
        return jump,channel
    except UserError:
        with contextlib.suppress(Exception):jump.close();raise
    except Exception as e:
        with contextlib.suppress(Exception):jump.close()
        target=host+':'+str(port)
        if isinstance(e,getattr(pm,'AuthenticationException',())):
            raise UserError('SSH: российский сервер '+ru['host']+':'+str(ru['port'])+' отклонил авторизацию при переходе к EU ('+target+').') from None
        if isinstance(e,(TimeoutError,socket.timeout)):
            raise UserError('SSH: не удалось открыть канал к EU '+target+' через российский сервер '+ru['host']+'.') from None
        raise UserError('SSH: переход к EU '+target+' через RU '+ru['host']+' не удался ('+type(e).__name__+'). Проверьте, что с RU доступен SSH EU, или выберите GRE после установки.') from None

def _read_host_key(sock,label):
    pm=get_paramiko();transport=None
    try:
        transport=pm.Transport(sock);transport.start_client(timeout=8);return fingerprint(transport.get_remote_server_key())
    except Exception as error:
        raise UserError('Не удалось автоматически получить SSH-ключ: '+label+' ('+type(error).__name__+'). Проверьте адрес, порт и доступность. Пароль ещё не передавался.') from None
    finally:
        if transport:transport.close()

def fingerprints(settings):
    """Read host keys. Direct path never authenticates; via_ru authenticates to RU only to reach EU."""
    result={};jump=None;channel=None
    try:
        ru=settings['ru'];ru_label='российский сервер '+ru['host']+':'+str(ru['port'])
        try:
            sock=socket.create_connection((ru['host'],ru['port']),timeout=8)
            try:result['ru']=_read_host_key(sock,ru_label)
            finally:sock.close()
        except UserError:raise
        except Exception as error:
            raise UserError('Не удалось автоматически получить SSH-ключ: '+ru_label+' ('+type(error).__name__+'). Проверьте адрес, порт и доступность. Пароль ещё не передавался.') from None
        nl=settings['nl'];label='зарубежный сервер '+nl['host']+':'+str(nl['port'])
        if settings.get('eu_ssh')=='via_ru':
            jump_settings=dict(settings);jump_settings['ru']=dict(settings['ru'],fingerprint=result['ru'])
            jump,channel=_open_eu_channel(jump_settings)
            host,port=eu_connect_target(settings)
            label+=' через RU → '+host+':'+str(port)
            result['nl']=_read_host_key(channel,label)
        else:
            try:
                sock=socket.create_connection((nl['host'],nl['port']),timeout=8)
                try:result['nl']=_read_host_key(sock,label)
                finally:sock.close()
            except UserError:raise
            except Exception as error:
                raise UserError('Не удалось автоматически получить SSH-ключ: '+label+' ('+type(error).__name__+'). Проверьте адрес, порт и доступность. Пароль ещё не передавался.') from None
        return result
    finally:
        if channel:
            with contextlib.suppress(Exception):channel.close()
        if jump:
            with contextlib.suppress(Exception):jump.close()

class Remote(engine.Endpoint):
    def __init__(self,role,settings,jump=None,connect_host=None,connect_port=None):
        self.role=role;self.settings=settings;self.client=None;self.host=settings['host']
        self.jump=jump;self.jump_client=None
        self.connect_host=connect_host or settings['host'];self.connect_port=settings.get('port',22) if connect_port is None else connect_port
        self.guard=None;self.guard_stop=threading.Event();self.guard_write=threading.Lock();self.guard_thread=None;self.guard_failed=False;self.guard_path=None;self.guard_token=None;self.bootstrap_lock=False;self.lock_release_pending=False
    def connect(self):
        pm=get_paramiko();expected=self.settings['fingerprint']
        if not expected:raise UserError('Сначала получите и подтвердите SSH-отпечатки.')
        class Pin(pm.MissingHostKeyPolicy):
            def missing_host_key(_self,client,hostname,key):
                if not secrets.compare_digest(fingerprint(key),expected):raise UserError('SSH-отпечаток сервера изменился. Соединение отклонено.')
        client=pm.SSHClient();client.set_missing_host_key_policy(Pin());self.client=client
        s=self.settings;options=_auth_options(pm,s);options['hostname']=self.connect_host;options['port']=self.connect_port
        try:
            if self.jump:
                # Jump settings must already carry the trusted RU fingerprint.
                jump_settings=dict(self.jump)
                if not jump_settings.get('fingerprint'):raise UserError('Сначала получите и подтвердите SSH-отпечатки.')
                class JumpPin(pm.MissingHostKeyPolicy):
                    def missing_host_key(_self,client,hostname,key):
                        if not secrets.compare_digest(fingerprint(key),jump_settings['fingerprint']):raise UserError('SSH-отпечаток сервера изменился. Соединение отклонено.')
                jump=pm.SSHClient();jump.set_missing_host_key_policy(JumpPin())
                jump.connect(**_auth_options(pm,jump_settings));jump.get_transport().set_keepalive(20);self.jump_client=jump
                channel=jump.get_transport().open_channel('direct-tcpip',(self.connect_host,self.connect_port),('127.0.0.1',0),timeout=12)
                options['sock']=channel
            client.connect(**options)
        except UserError:raise
        except Exception as e:
            via=' через RU' if self.jump else ''
            server=('российский' if self.role=='ru' else 'зарубежный')+' сервер '+self.host+':'+str(s['port'])+via
            if self.jump and (self.connect_host,self.connect_port)!=(self.host,s['port']):server+=' → '+self.connect_host+':'+str(self.connect_port)
            if isinstance(e,getattr(pm,'AuthenticationException',())):
                raise UserError('SSH: '+server+' отклонил авторизацию ('+('пароль' if s['method']=='password' else 'ключ')+'). Проверьте данные именно этого сервера и разрешённый способ входа. Получение отпечатка не проверяет пароль.') from None
            if isinstance(e,(TimeoutError,socket.timeout)):
                raise UserError('SSH: превышено время подключения или авторизации: '+server+'.') from None
            raise UserError('SSH: не удалось подключиться: '+server+' ('+type(e).__name__+'). Проверьте адрес, порт и доступность сервера.') from None
        client.get_transport().set_keepalive(20)
        self.shell('test "$(id -u)" = 0',quiet=True)
    def execute(self,command,payload='',limit=1800,_unlocked=False):
        if not _unlocked:
            if self.guard_failed:raise UserError('Связь с блокировкой сервера потеряна. Перечитайте состояние перед новой операцией.')
            if self.bootstrap_lock and self.execute('command -v python3 || true',limit=15,_unlocked=True).strip():self.lock()
            if self.guard:command=ssh_guard.protected_command(command,self.guard_path,self.guard_token)
            elif self.bootstrap_lock:command='flock -n -E 73 /run/ovpn-installer.lock '+command
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
            if status==73 and self.bootstrap_lock:raise UserError('На сервере уже выполняется другая операция.')
            if b'VPNAI_LOCK_LOST' in b''.join(chunks):raise UserError('Блокировка сервера недоступна. Команда не запущена; перечитайте состояние перед повторением.')
            detail=engine.diagnostic_message(b''.join(chunks).decode(errors='replace'))
            if detail:raise UserError(('Российский' if self.role=='ru' else 'Зарубежный')+' сервер: '+detail+' (код '+str(status)+').')
            raise UserError('Команда на '+('российском' if self.role=='ru' else 'зарубежном')+' сервере завершилась с ошибкой'+(' (код '+str(status)+')' if status else '')+'. Проверьте журнал systemd/пакетов на сервере. Пароли в журнал приложения не выводятся.')
        return b''.join(chunks).decode(errors='replace')
    def shell(self,script,quiet=False):return self.execute('bash -s',script)
    def python(self,code,data=None):
        wrapper='import json,sys\nDATA=json.load(sys.stdin)\n'+code
        return self.execute('python3 -c '+shlex.quote(wrapper),json.dumps(data))
    def lock(self):
        if self.guard:
            if self.guard_failed:raise UserError('Связь с блокировкой сервера потеряна.')
            return
        if not self.execute('command -v python3 || true',limit=15,_unlocked=True).strip():
            # Bootstrap a clean server under command-scoped flock; children inherit that lock.
            self.bootstrap_lock=True;return
        token=secrets.token_hex(16);path='/run/vpnai-lock-'+token+'.sock'
        inp,out,err=self.client.exec_command(ssh_guard.server_command(path,token),timeout=10)
        channel=out.channel;channel.settimeout(5)
        try:
            reply=out.readline(64)
            if isinstance(reply,bytes):reply=reply.decode()
            if reply.strip()!='READY':raise UserError('На сервере уже выполняется другая операция.' if reply.strip()=='BUSY' else 'Не удалось получить служебную блокировку сервера.')
        except BaseException:
            channel.close();raise
        self.guard=(inp,out,err);self.guard_path=path;self.guard_token=token;self.bootstrap_lock=False;self.guard_failed=False;self.guard_stop.clear()
        guard=self.guard
        def heartbeat():
            while not self.guard_stop.wait(ssh_guard.HEARTBEAT_SECONDS):
                try:
                    with self.guard_write:
                        if self.guard is not guard:return
                        guard[0].write('PING\n');guard[0].flush()
                except Exception:self.guard_failed=True;return
        self.guard_thread=threading.Thread(target=heartbeat,name='ssh-lock-heartbeat',daemon=True);self.guard_thread.start()
    def close(self):
        self.guard_stop.set()
        try:
            if self.guard:
                channel=self.guard[1].channel;released=False
                try:
                    with self.guard_write:
                        self.guard[0].write('QUIT\n');self.guard[0].flush();channel.shutdown_write()
                    deadline=time.monotonic()+3
                    while not channel.exit_status_ready() and time.monotonic()<deadline:time.sleep(.03)
                    released=channel.exit_status_ready() and channel.recv_exit_status()==0
                except Exception:pass
                finally:
                    self.lock_release_pending=not released
                    with contextlib.suppress(Exception):channel.close()
        finally:
            if self.client:
                with contextlib.suppress(Exception):self.client.close()
            if self.jump_client:
                with contextlib.suppress(Exception):self.jump_client.close()
            if self.guard_thread and self.guard_thread is not threading.current_thread():self.guard_thread.join(timeout=1)
            self.guard=None;self.guard_thread=None;self.client=None;self.jump_client=None;self.guard_path=None;self.guard_token=None;self.bootstrap_lock=False;self.settings.clear()

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
        if c['routing_mode']!='split':
            s=s.replace('client-connect /usr/local/libexec/ovpn-split-connect','push "redirect-gateway def1"')
            s=s.replace('client-connect "/usr/local/libexec/ovpn-session-limit connect"','client-connect "/usr/local/libexec/ovpn-session-limit connect-full"\npush "redirect-gateway def1"')
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

def remove_installation(job,c,ru,nl,prepared=None):
    import backups
    snapshot=backups.snapshot({k:c[k] for k in ('ru_ip','nl_ip')},'before-removal')
    pair={k:c[k] for k in ('ru_ip','nl_ip')};report={};job.report['removal']=report
    endpoints=(nl,ru)
    for ep in endpoints:
        job.checkpoint();role=ep.role
        job.event('Проверка удаления',12,'Проверка данных владельца и готовности: '+('зарубежный' if role=='nl' else 'российский')+' сервер.')
        try:
            if prepared and not prepared[role]['configured']:report[role]={'already_removed':True,'finalize':False}
            else:report[role]=json.loads(ep.python(CLEAN_PREFLIGHT,{'role':role,'pair':pair}))
        except UserError as e:raise UserError('Проверка перед удалением: '+str(e)) from None
    # Both backups must finish before any service is stopped on either host.
    for ep in endpoints:
        job.checkpoint();role=ep.role;meta=report[role]
        if prepared:
            meta['backup']=prepared[role]['backup'];continue
        job.event('Резервная копия',15,'Создание закрытого архива перед удалением: '+('зарубежный' if role=='nl' else 'российский')+' сервер.')
        try:meta['backup']=json.loads(ep.python(CLEAN_BACKUP,{'role':role,'pair':pair,'snapshot':snapshot,'force_snapshot':True,'allow_empty':True}))['backup']
        except UserError as e:raise UserError('Резервное копирование перед удалением: '+str(e)) from None
    for index,ep in enumerate(endpoints):
        job.checkpoint();role=ep.role;meta=report[role]
        if meta['already_removed'] and not meta.get('finalize'):meta['complete']=True;continue
        job.event('Удаление',25+index*30,'Удаление компонентов своей установки: '+('зарубежный' if role=='nl' else 'российский')+' сервер.')
        try:ep.python(CLEAN,{'role':role,'pair':pair,'backup':meta['backup'],'rollback':engine.ROLLBACK})
        except UserError as e:raise UserError('Удаление: '+str(e)+' Уже завершённые этапы указаны в отчёте; повторный запуск учитывает частичное удаление.') from None
        meta['complete']=True


def available_backups(settings):
    import backups
    endpoints=[]
    try:
        for role in ('ru','nl'):
            ep=make_remote(role,settings);endpoints.append(ep);ep.connect()
        pair={role+'_ip':settings[role]['host'] for role in ('ru','nl')}
        rows=[json.loads(backups.remote(ep,pair,'list')) for ep in endpoints]
        return backups.catalogue(*rows)
    finally:
        for ep in endpoints:ep.close()

def restore_archive(job,s,c,ru,nl,inv):
    import backups
    pair={k:c[k] for k in ('ru_ip','nl_ip')};stages={};guards={};changed=False
    try:
        job.event('Архивы',10,'Проверка выбранного архива на российском сервере и его пары на зарубежном.')
        ru_info,nl_info=backups.find_pair(ru,nl,pair,s['restore_backup'])
        info={ru.role:ru_info,nl.role:nl_info}
        private=json.loads(backups.remote(ru,pair,'inspect',name=ru_info['name']))
        state=private['state'];saved=dict(state['config'])
        engine.validate(saved)
        # Never let saved host aliases or SSH parameters replace current authenticated connections.
        saved['nl_host']='root@'+pair['nl_ip'];saved['ssh_port']=s['nl']['port'];saved['ssh_key']=None
        saved['initial_user']=s['initial_user'];saved['https_relay']=True
        for ep in (ru,nl):
            if not inv[ep.role]['managed']:
                class ReadOnly:
                    role=ep.role
                    python=ep.python
                    def write(self,*args,**kwargs):pass
                engine.preflight(saved,ReadOnly(),inv[ep.role],False)
        for ep in (ru,nl):
            job.checkpoint();token=secrets.token_hex(12);meta=info[ep.role]
            prepared=json.loads(backups.remote(ep,pair,'stage',name=meta['name'],sha256=meta['sha256'],stage=token))
            stages[ep.role]=token
        safety=backups.snapshot(pair,'before-archive-restore')
        job.event('Резервная копия',15,'Сохранение текущего состояния обоих серверов под общим именем.')
        for ep in (ru,nl):
            job.checkpoint();guards[ep.role]=json.loads(ep.python(CLEAN_BACKUP,{'role':ep.role,'pair':pair,'snapshot':safety,'force_snapshot':True,'allow_empty':True}))
        job.report['archive_restore']={'ru_archive':ru_info['name'],'foreign_archive':nl_info['name'],'safety_backups':{k:v['backup'] for k,v in guards.items()}}
        job.checkpoint();changed=True
        remove_installation(job,saved,ru,nl,prepared=guards)
        fresh={ep.role:ep.inventory() for ep in (ru,nl)}
        for ep in (ru,nl):
            engine.preflight(saved,ep,fresh[ep.role],False)
            ep.write('/var/lib/ovpn-installer/role',ep.role+'\n')
        state=dict(state,version=2,complete=False,config=saved)
        ru.write('/var/lib/ovpn-installer/state.json',json.dumps(state))
        for ep in (ru,nl):
            job.event('Восстановление',35,'Восстановление проверенных данных: '+('российский' if ep.role=='ru' else 'зарубежный')+' сервер.')
            backups.remote(ep,pair,'apply',stage=stages[ep.role],sha256=info[ep.role]['sha256'])
        job.report['archive_restore']['data_restored']=True
        return saved
    except backups.BackupError as error:raise UserError(str(error)) from None
    except BaseException:
        if changed:
            job.report['archive_restore_error']='Операция не завершена; данные исходной конфигурации сохранены в защитных архивах на обоих серверах.'
            for ep in (ru,nl):
                with contextlib.suppress(Exception):ep.shell(engine.ROLLBACK,quiet=True)
        raise
    finally:
        for ep in (ru,nl):
            if ep.role in stages:
                with contextlib.suppress(Exception):backups.remote(ep,pair,'discard',stage=stages[ep.role])


class Job:
    def __init__(self,settings):
        self.ssh_connected=False;self.id=secrets.token_urlsafe(18);self.demo=settings['demo'];self.settings=settings;self.cancel=threading.Event();self.lock=threading.RLock();self.status='running';self.phase='Подготовка';self.progress=0;self.events=[];self.report={'demo':self.demo,'action':settings['action'],'routing':settings['routing'],'auth':settings['auth'],'update_packages':settings['update_packages'],'servers':{r:settings[r]['host'] for r in ('ru','nl')},'initial_user':settings['initial_user'],'lists':{'ru':settings['ru_routes'],'eu':settings['eu_routes']}};self.artifact=None;self.expires=0
    def event(self,phase,progress,message):
        with self.lock:self.phase=phase;self.progress=progress;self.events.append({'time':time.strftime('%H:%M:%S'),'message':message})
    def checkpoint(self):
        if self.cancel.is_set():raise Cancelled('Операция остановлена между этапами.')
    def public(self):
        with self.lock:return {'id':self.id,'status':self.status,'phase':self.phase,'progress':self.progress,'events':list(self.events),'report':self.report,'download':bool(self.artifact and time.time()<self.expires),'demo':self.demo,'ssh_connected':self.ssh_connected}
    def run(self):
        try:
            real_run(self)
            with self.lock:self.status='success';self.progress=100
        except Cancelled as e:
            self.event('Остановлено',self.progress,str(e));self.status='cancelled'
        except Exception as e:
            message=str(e) if isinstance(e,(UserError,engine.InstallError)) else 'Операция не завершена ('+type(e).__name__+'). Проверьте соединение и повторите проверку серверов.'
            self.event('Ошибка',self.progress,message);self.status='error'
        finally:
            self.settings.clear()

def config(s):
    return {'ru_ip':s['ru']['host'],'nl_ip':s['nl']['host'],'nl_host':'root@'+s['nl']['host'],'ssh_port':s['nl']['port'],'ssh_key':None,'initial_user':s['initial_user'],'vpn_net':'10.77.0.0/24','tcp_net':'10.79.0.0/24','gre_net':'10.78.0.0/30','ovpn_port':s['vpn_port'],'source_url':'https://iplist.opencck.org/?format=json&data=cidr4','routing_mode':s['routing'],'auth_mode':s['auth'],'connection_limit':s.get('connection_limit')}

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
    endpoints=[make_remote('ru',s),make_remote('nl',s)];ru,nl=endpoints;mutated=False;previous=None;current_update=False;update_snapshot=None
    try:
        ssh_note='EU через RU ('+( 'GRE '+GRE_EU_HOST if s.get('eu_target')=='gre' else 'публичный IP')+').' if s.get('eu_ssh')=='via_ru' else 'оба сервера напрямую.'
        job.event('SSH',3,'Подключение к серверам с проверкой отпечатков: '+ssh_note)
        for ep in endpoints:job.checkpoint();ep.connect()
        job.ssh_connected=True
        if s['action'] not in ('check','verify'):
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
        if s['action'] in ('check','verify'):
            from diagnostics import inspect_servers
            result=inspect_servers(c,endpoints,inv,verify=s['action']=='verify')
            job.report['requested_routing']=job.report.pop('routing',s['routing'])
            job.report['requested_auth']=job.report.pop('auth',s['auth'])
            try:
                state=json.loads(ru.python("import pathlib; p=pathlib.Path('/var/lib/ovpn-installer/state.json'); print(p.read_text() if p.exists() else 'null')"))
                if state is not None and (not isinstance(state,dict) or not isinstance(state.get('config'),dict)):raise ValueError('Invalid installer state')
                if state and any(state.get('config',{}).get(k)!=c[k] for k in ('ru_ip','nl_ip')):
                    result['warnings'].append('Служебный файл относится к другой паре серверов и не использован для определения режимов.');state=None
                modes=installed_modes(ru,state or {'config':{}},allow_incomplete=False)
                job.report.update(installed=modes,routing=modes['routing'],auth=modes['auth'])
                if state and modes['legacy']:result['warnings'].append('Обнаружена старая установка; настройки только прочитаны.')
            except (UserError,ValueError,KeyError,TypeError):
                job.report.update(routing='unknown',auth='unknown')
                result['warnings'].append('Режимы маршрутизации и входа не удалось определить; выбранные в форме параметры не считаются фактическими.')

            job.report['details']={r:{k:inv[r].get(k) for k in ('routes','routes6','addr','swan','reserved_files')} for r in ('ru','nl')}
            job.report.update(action=s['action'],servers={r:s[r]['host'] for r in ('ru','nl')},os={r:inv[r]['os'] for r in ('ru','nl')},system=system,existing={r:inv[r]['managed'] for r in ('ru','nl')},diagnostics=result,checks=result['checks'],warnings=result['warnings'],full_check=result['complete'])
            for warning in result['warnings']:job.event('Диагностика',10,warning)
            for item in result['checks']:
                if item['passed'] is not True:job.event('Диагностика',80,item['server']+': '+item['check']+' — '+('замечание' if item['passed'] is False else 'неизвестно')+'. '+item['detail'])
            failed=[x for x in result['checks'] if x['passed'] is False]
            if failed:raise UserError('Диагностика завершена: есть замечания. Смотрите результаты отдельных проверок в отчёте; переустановка автоматически не требуется.')
            job.report['notice']='Проверка состояния завершена. '+('Часть проверок недоступна; результат неполный. ' if not result['complete'] else '')+'Сквозная работа клиентского VPN не проверялась.'
            job.event('Проверка завершена',100,job.report['notice']);return
        previous=json.loads(ru.python("import pathlib; p=pathlib.Path('/var/lib/ovpn-installer/state.json'); print(p.read_text() if p.exists() else 'null')"))
        job.report={'demo':False,'action':s['action'],'servers':{r:s[r]['host'] for r in ('ru','nl')},'existing':{r:inv[r]['managed'] for r in ('ru','nl')},'os':{r:inv[r]['os'] for r in ('ru','nl')},'routing':s['routing'],'auth':s['auth'],'update_packages':s['update_packages'],'initial_user':s['initial_user'],'lists':{'ru':s['ru_routes'],'eu':s['eu_routes']},'system':system,'checks':[]}
        if previous and any(previous['config'].get(k)!=c[k] for k in ('ru_ip','nl_ip')):raise UserError('Сохранённая установка относится к другой паре серверов.')
        if previous is None and s['action']=='resume' and not s.get('restore_backup'):
            import legacy_update
            legacy_update.run(job,ru,nl)
            return
        preserved_dns=None
        if s['action'] in ('install','resume') and s.get('dns') is None and not s.get('restore_backup'):
            import dns_backend
            preserved_dns=dns_backend.capture(ru)
        if s['action']=='resume' and s.get('restore_backup'):
            import dns_backend
            current_dns=dns_backend.saved(ru)
            if current_dns and current_dns['servers']:raise UserError('Перед восстановлением архива отключите DNS от сервера в управлении и переподключитесь. Затем повторите восстановление.')
            c=restore_archive(job,s,c,ru,nl,inv);mutated=True
            preserved_dns=dns_backend.capture(ru)
            inv={ep.role:ep.inventory() for ep in endpoints}
            previous=json.loads(ru.python("import pathlib; print(pathlib.Path('/var/lib/ovpn-installer/state.json').read_text())"))
            job.report['routing']=c['routing_mode'];job.report['auth']=c['auth_mode']
        detected=None
        if previous and s['action'] in ('check','verify','resume'):
            job.event('Режим сервера',9,'Чтение настроенных режимов OpenVPN.')
            detected=installed_modes(ru,previous,allow_incomplete=s['action']=='resume')
            job.report['installed']=detected;job.report['requested_routing']=s['routing'];job.report['requested_auth']=s['auth']
            job.report['routing']=detected['routing'];job.report['auth']=detected['auth'];job.report['lists_from_server']=True
            warnings=[]
            if detected.get('source')=='saved-incomplete':warnings.append('Обнаружена незавершённая установка. Обновление применит выбранные в форме режимы.')
            if detected['legacy']:warnings.append('Обнаружена старая установка; обновление развернёт актуальные компоненты.' if s['action']=='resume' else 'Обнаружена старая установка; проверка учитывает её формат без изменения серверов.')
            if s['action'] in ('check','verify') and detected['routing']!=s['routing']:warnings.append('Фактическая маршрутизация: '+{'full_mixed':'весь IPv4 через VPN с выбором RU/NL','full_nl':'весь IPv4 через зарубежный сервер','split':'раздельные маршруты','unknown':'не удалось однозначно определить'}[detected['routing']]+'. Выбор в форме при проверке её не меняет.')
            if s['action'] in ('check','verify') and detected['auth']!=s['auth']:warnings.append('Авторизация в отчёте взята из действующих настроек сервера.')
            job.report['warnings']=warnings
            for warning in warnings:job.event('Режим сервера',10,warning)
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
            c=dict(saved);c.setdefault('routing_mode','split');c.setdefault('auth_mode','password')
            if s['action']=='resume':
                if s.get('restore_backup'):c['initial_user']=s['initial_user']
                else:
                    current_update=True;update_snapshot=update_configuration(ru,s,previous)
                    if not s.get('update_revision') or not secrets.compare_digest(s['update_revision'],update_snapshot['revision']):raise UserError('Конфигурация сервера изменилась или не загружена. Загрузите текущие настройки и проверьте изменения перед запуском.')
                    c.update(routing_mode=s['routing'],auth_mode=s['auth'],ovpn_port=s['vpn_port'],initial_user='' if update_snapshot['user_count'] else s['initial_user'])
                    job.report['initial_user']=c['initial_user'];job.report['users_preserved']=update_snapshot['user_count'];job.report['lists_from_server']=False
                    job.report['lists']={'ru':s['ru_routes'],'eu':s['eu_routes']}
                    backup_update(job,c,ru,nl)
                    job.event('Обновление',12,'Текущее состояние сохранено в парные архивы. Будут применены настройки формы; пользователи и сертификаты сохраняются.')
            job.report['routing']=c['routing_mode'];job.report['auth']=c['auth_mode']
        for ep in endpoints:job.checkpoint();engine.preflight(c,ep,inv[ep.role],bool(previous))
        c['https_relay']=True
        c['connection_limit']=s.get('connection_limit')
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
        job.checkpoint();job.event('Пользователи и списки',46,'Создание PKI и применение выбранных списков маршрутов.')
        # Preserve existing lists on resume. Fresh installations receive only user-entered addresses.
        ru.write('/etc/ovpn-routing/force-ru.txt','\n'.join(s['ru_routes'])+'\n',preserve=not current_update)
        ru.write('/etc/ovpn-routing/extra-nl.txt','\n'.join(s['eu_routes'])+'\n',preserve=not current_update)
        engine.initialize_ru(c,ru)
        if current_update and c['auth_mode']=='password':
            generated=json.loads(ru.python(UPDATE_PASSWORDS))['generated'];job.report['passwords_generated']=generated
            if generated:job.report.setdefault('warnings',[]).append('Для пользователей без сохранённого действующего пароля созданы новые пароли. Получите их в профилях: '+', '.join(generated))
        for ep in (nl,ru):
            job.checkpoint();ep.shell('set -e\nsystemctl daemon-reload\nsystemctl enable --now ovpn-network ovpn-tcp-network strongswan\nsystemctl restart strongswan\nswanctl --load-all\n')
        if current_update:
            for ep in (nl,ru):ep.shell('set -e\nsystemctl restart ovpn-network ovpn-tcp-network\n',quiet=True)
        job.checkpoint();job.event('HTTPS',60,'Проверка HTTPS-сертификата; выпуск и продление через защищённый канал NL. HTTP-проверка доступна на RU TCP 80.')
        job.report['https']=engine.setup_https(c,ru,nl)
        if job.report['https'].get('renewal',{}).get('available') is False:
            warning='Рабочий сертификат сохранён, но Let’s Encrypt сейчас недоступен. Автопродление повторит проверку каждый час; проверьте журнал ovpn-cert-renew.'
            job.report.setdefault('warnings',[]).append(warning);job.event('Предупреждение HTTPS',65,warning)
        job.checkpoint();job.event('Запуск VPN',75,'Защищённый туннель и OpenVPN UDP/TCP.')
        if preserved_dns:
            import dns_backend
            dns_backend.preserve_push(ru,preserved_dns)
        job.report['initial_user_result']=engine.activate(c,ru,nl,create_only_if_empty=True) if current_update else engine.activate(c,ru,nl)
        if current_update and job.report['initial_user_result'].get('skipped_existing'):
            c['initial_user']='';job.report['initial_user']=''
        # Apply comment and regenerate all profiles according to the selected auth mode.
        ru.python(r'''import pathlib,subprocess,fcntl
with open('/run/ovpn-user.lock','a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 p=pathlib.Path('/etc/openvpn/server/users.json');users=json.loads(p.read_text())
 if DATA['name'] in users and not DATA['preserve']:users[DATA['name']]['comment']=DATA['comment'];p.write_text(json.dumps(users,ensure_ascii=False,indent=2))
for name,record in users.items():
 if record.get('enabled') and not record.get('deleted'):subprocess.run(['ovpn-user','profiles',name],check=True,stdout=subprocess.DEVNULL)
record=users.get(DATA['name'],{})
folder=pathlib.Path('/root/ovpn-profiles')
if DATA['name'] and (not record.get('enabled') or record.get('deleted') or not all((folder/(DATA['name']+suffix)).is_file() for suffix in ('-UDP.ovpn','-TCP.ovpn'))):
 print('VPNAI_DIAG:INITIAL_USER');raise SystemExit(1)
''',{'name':c['initial_user'],'comment':s['comment'],'preserve':bool(previous)})
        ru.shell('set -e\nsystemctl restart openvpn-server@ru openvpn-server@ru-tcp\n')
        job.checkpoint();job.event('Проверка VPN',88,'Проверка служб, HTTPS и двух выходов через изолированные тестовые сети.')
        job.report['verification']=engine.verify(c,ru,nl)
        if not current_update or update_snapshot['active_user_count'] or not update_snapshot['user_count']:
            job.artifact=collect(ru);job.expires=time.time()+600
        for ep in endpoints:ep.python("import pathlib;pathlib.Path('/var/lib/ovpn-installer/rolled-back').unlink(missing_ok=True)")
        state['complete']=True;ru.write('/var/lib/ovpn-installer/state.json',json.dumps(state))
        import dns_backend
        try:
            requested_dns=s.get('dns') if not s.get('restore_backup') else None
            effective_dns=requested_dns if requested_dns is not None else (None if preserved_dns and not preserved_dns['managed'] else dns_backend.saved(ru))
            if effective_dns is not None:
                job.event('DNS',97,'Применение DNS для VPN-клиентов с резервной копией настроек.')
                job.report['dns']=dict(dns_backend.apply_install(effective_dns,ru,nl),applied=True)
        except UserError as error:
            job.report['dns']={'applied':None,'error':str(error)}
            job.event('DNS требует проверки',98,'VPN установлен. '+str(error))
        job.report['notice']='Серверные проверки завершены. Дополнительно импортируйте профиль и проверьте VPN со своего устройства.'
        if current_update:
            job.report['notice']='Обновление завершено. Настройки применены, серверное меню обновлено, существующие пользователи сохранены. Скачайте обновлённые профили и переподключите устройства.'
            if job.report.get('passwords_generated'):job.report['notice']+=' Для пользователей без сохранённого пароля созданы новые пароли; они включены в архив профилей.'
        if any(info['reboot_required'] for info in system.values()):job.report['notice']+=' Обновления ОС требуют перезагрузки: '+', '.join('российский сервер' if r=='ru' else 'зарубежный сервер' for r,info in system.items() if info['reboot_required'])+'. Она автоматически не выполнялась.'
        if 'dns' in job.report and job.report['dns'].get('applied') is not True:job.report['notice']+=' Проверьте DNS: '+job.report['dns']['error']
        job.event('Готово',100,'Установка завершена. Профили доступны для скачивания 10 минут; меню на сервере: /root/menu.sh.')
    except BaseException:
        if current_update and mutated:
            job.event('Обновление не завершено',job.progress,'Защитные архивы сохранены: '+str(job.report.get('update_backups',{}))+'. Данные пользователей не удалены; проверьте серверы или восстановите парный архив. Автоматическое удаление компонентов не выполнялось.')
        elif mutated:
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
