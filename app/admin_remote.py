# -*- coding: utf-8 -*-
"""Executed over pinned SSH, with DATA supplied on stdin. No shell interpolation."""
import base64, contextlib, hashlib, hmac, io, json, os, pathlib, re, runpy, subprocess, time, zipfile, secrets

try:
    import fcntl
except ImportError:
    fcntl=None

def tunnel_status(config,expected_peer=None):
    import ipaddress
    result={'state':'unknown','latency_ms':None,'detail':'Не удалось проверить GRE / IPsec.'}
    def command(args):return subprocess.run(args,capture_output=True,text=True,timeout=4,env=dict(os.environ,LC_ALL='C'))
    try:
        net=ipaddress.ip_network(config.get('gre_net',''),strict=True)
        if net.version!=4 or net.prefixlen!=30 or not net.is_private:return dict(result,detail='GRE-подсеть не найдена в конфигурации.')
        peer=str(ipaddress.ip_address(config['nl_ip']))
        if expected_peer and peer!=expected_peer:return dict(result,detail='Конфигурация GRE относится к другой паре серверов.')
        links=command(['ip','-j','-d','link','show','dev','gre-nl'])
        if links.returncode:return dict(result,state='down',detail='Интерфейс gre-nl отсутствует.')
        link=json.loads(links.stdout)[0];info=link.get('linkinfo',{})
        if info.get('info_kind')!='gre' or 'UP' not in link.get('flags',[]):return dict(result,state='down',detail='Интерфейс GRE выключен.')
        if info.get('info_data',{}).get('remote')!=peer:return dict(result,state='down',detail='GRE направлен на другой сервер.')
        sas=command(['swanctl','--list-sas'])
        if sas.returncode:return dict(result,detail='Статус IPsec недоступен.')
        block=re.search(r'^ovpn-gre:[^\n]*(?:\n[ \t]+[^\n]*)*',sas.stdout,re.M)
        if not block or not re.search(r'^\s+gre:\s+#\d+[^\n]*\bINSTALLED\b',block.group(),re.M) or not re.search(r'@\s*'+re.escape(peer)+r'(?:\[|\s|$)',block.group()):
            return dict(result,state='down',detail='IPsec для GRE не установлен.')
        ping=command(['ping','-n','-c','1','-W','2','-I','gre-nl',str(net[2])])
        if ping.returncode:return dict(result,state='down',detail='GRE-партнёр не ответил на проверку.')
        match=re.search(r'time[=<]([0-9.]+)\s*ms',ping.stdout)
        return dict(result,state='up',latency_ms=float(match[1]) if match else None,detail='GRE-партнёр доступен, IPsec установлен.')
    except (OSError,ValueError,KeyError,IndexError,subprocess.TimeoutExpired):return result

def execute(data):
    os.umask(0o077)
    operation=data['operation']
    base=pathlib.Path('/etc/openvpn/server'); profiles=pathlib.Path('/root/ovpn-profiles')
    def run(args, password=None):
        result=subprocess.run(args,input=password,text=True,capture_output=True,timeout=120)
        if result.returncode:raise ValueError('Серверная команда не выполнена. Проверьте состояние VPN и журнал сервера.')
        return result.stdout
    def records():return json.loads((base/'users.json').read_text())
    def credential(name):
        record=records().get(name,{})
        if not record.get('enabled') or record.get('deleted'):raise ValueError('Пользователь неактивен.')
        file=profiles/(name+'-credentials.txt')
        password=next((line[10:] for line in file.read_text().splitlines() if line.startswith('Password: ')),None) if file.is_file() else None
        try:valid=password is not None and hmac.compare_digest(hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(record['salt']),300000).hex(),record['hash'])
        except (KeyError,ValueError):valid=False
        return {'password':password if valid else None,'comment':record.get('comment','')}
    if operation=='metrics':
        memory={line.split(':')[0]:int(line.split()[1]) for line in pathlib.Path('/proc/meminfo').read_text().splitlines()}
        release={}
        for line in pathlib.Path('/etc/os-release').read_text().splitlines():
            if '=' in line:
                key,value=line.split('=',1);release[key]=value.strip('"')
        def cpu():return list(map(int,pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:]))
        before=cpu();time.sleep(.15);after=cpu();total=sum(after[:8])-sum(before[:8]);idle=sum(after[3:5])-sum(before[3:5])
        return {'os':release.get('PRETTY_NAME','Linux'),'cpu':round(100*(1-idle/total),1) if total else 0,'memory_used':(memory['MemTotal']-memory.get('MemAvailable',memory.get('MemFree',0)))*1024,'memory_total':memory['MemTotal']*1024,'uptime':int(float(pathlib.Path('/proc/uptime').read_text().split()[0]))}
    if operation=='overview':
        module=runpy.run_path('/usr/local/libexec/ovpn-menu.py',run_name='vpnai_web_admin')
        warnings=[]
        try:raw=module['sessions']();sessions_available=True
        except OSError:raw=[];sessions_available=False;warnings.append('Не удалось прочитать активные подключения OpenVPN.')
        sessions=[]
        for row in raw:
            ip,port=module['peer_address'](row[2])
            sessions.append({'name':row[1],'client_ip':ip,'vpn_ip':row[3],'bytes_received':int(row[5]),'bytes_sent':int(row[6]),'since':int(row[8]) if len(row)>9 and row[8].isdigit() else None,'protocol':row[-1]})
        visible=[{'name':n,'comment':v.get('comment',''),'enabled':bool(v.get('enabled'))} for n,v in sorted(records().items()) if not v.get('deleted')]
        state=pathlib.Path('/var/lib/ovpn-installer/state.json')
        config=json.loads(state.read_text()) if state.exists() else {}
        return {'users':visible,'sessions':sessions,'sessions_available':sessions_available,'routing':config.get('config',config).get('routing_mode'),'warnings':warnings,'tunnel':tunnel_status(config.get('config',config),data.get('expected_peer'))}
    if operation=='routes':
        def custom(nl):return json.loads(run(['/usr/local/sbin/ovpn-custom']+(['--nl'] if nl else [])+['list']))
        source=pathlib.Path('/var/lib/ovpn-routing/source.json')
        return {'ru':custom(False),'eu':custom(True),'iplist':json.loads(source.read_text()) if source.exists() else []}
    name=data.get('name','')
    if operation in ('create','update','delete','credentials') and not re.fullmatch(r'[A-Za-z0-9_-]{1,48}',name):raise ValueError('Некорректный логин.')
    if operation=='credentials':
        with open('/run/ovpn-user.lock','a') as lock:
            fcntl.flock(lock,fcntl.LOCK_SH);return credential(name)
    if operation=='create':
        run(['/usr/local/sbin/ovpn-user','add',name,'--comment',data['comment']]);return {'created':True}
    if operation=='delete':
        run(['/usr/local/sbin/ovpn-user','delete',name]);return {'deleted':True}
    if operation=='update':
        # A password command takes the same user lock itself. Report partial success explicitly.
        password_changed=False
        if data.get('password'):
            run(['/usr/local/sbin/ovpn-user','passwd',name],data['password']+'\n');password_changed=True
        try:
            with open('/run/ovpn-user.lock','a') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX);users=records()
                if name not in users or users[name].get('deleted'):raise ValueError('Пользователь не найден.')
                users[name]['comment']=data['comment']
                tmp=base/'users.web.tmp'
                try:tmp.write_text(json.dumps(users,ensure_ascii=False,indent=2));tmp.chmod(0o600);tmp.replace(base/'users.json')
                finally:tmp.unlink(missing_ok=True)
        except Exception:
            if password_changed:raise ValueError('Пароль изменён, но комментарий не сохранён. Обновите данные перед повторной операцией.')
            raise
        return {'updated':True,'password_changed':password_changed}
    if operation=='route-change':
        args=['/usr/local/sbin/ovpn-custom']+(['--nl'] if data['kind']=='eu' else [])+[data['action'],data['cidr']]
        run(args);return {'updated':True}
    if operation=='iplist-update':
        return json.loads(run(['/usr/local/sbin/ovpn-routing','update']))
    if operation=='profile-link':
        import grp
        protocol=data.get('protocol')
        if protocol not in ('udp','tcp') or not re.fullmatch(r'[A-Za-z0-9_-]{1,48}',name):raise ValueError('Некорректный профиль.')
        with open('/run/ovpn-user.lock','a') as userlock:
            fcntl.flock(userlock,fcntl.LOCK_SH)
            user=records().get(name,{})
            if not user.get('enabled') or user.get('deleted'):raise ValueError('Пользователь неактивен.')
            profile=profiles/(name+'-'+protocol.upper()+'.ovpn')
            if profile.is_symlink() or not profile.is_file() or profile.stat().st_size>1024*1024:raise ValueError('Файл конфигурации не найден или повреждён.')
            body=profile.read_text();digest=hashlib.sha256(body.encode()).hexdigest()
            root=pathlib.Path('/var/lib/ovpn-links')
            if root.is_symlink() or not root.is_dir():raise ValueError('Сначала настройте HTTPS-ссылки на российском сервере.')
            gid=grp.getgrnam('ovpn-links').gr_gid
            with open('/run/ovpn-links.lock','a') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX)
                token=data.get('token','');entry=None
                if re.fullmatch(r'[A-Za-z0-9_-]{43}',token):
                    file=root/(hashlib.sha256(token.encode()).hexdigest()+'.json')
                    try:
                        old=json.loads(file.read_text())
                        if old.get('expires',0)>time.time() and old.get('usernames')==[name] and old.get('protocol')==protocol and hashlib.sha256(old.get('profile','').encode()).hexdigest()==digest:entry=old
                    except (OSError,ValueError):pass
                if entry is None:
                    token=secrets.token_urlsafe(32);entry={'username':name+'-'+protocol.upper(),'usernames':[name],'profile':body,'protocol':protocol,'expires':int(time.time())+600}
                    file=root/(hashlib.sha256(token.encode()).hexdigest()+'.json')
                    fd=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                    try:
                        os.fchown(fd,0,gid)
                        with os.fdopen(fd,'w',encoding='utf-8') as stream:
                            fd=None;json.dump(entry,stream);stream.flush();os.fsync(stream.fileno());os.fchmod(stream.fileno(),0o640)
                    except BaseException:
                        if fd is not None:os.close(fd)
                        with contextlib.suppress(FileNotFoundError):file.unlink()
                        raise
                return {'url':'https://'+data['public_host']+'/d/'+token+'/profile.ovpn','token':token,'expires':entry['expires'],'server_time':time.time(),'filename':name+'-'+protocol.upper()+'.ovpn'}
    if operation=='link':
        args=['/usr/local/sbin/ovpn-link','create',name] if name else ['/usr/local/sbin/ovpn-link','create-all']
        result=json.loads(run(args));result['server_time']=time.time();return result
    if operation=='profiles':
        with open('/run/ovpn-user.lock','a') as lock:
            fcntl.flock(lock,fcntl.LOCK_SH)
            available=records();names=[name] if name else sorted(available)
            names=[n for n in names if available.get(n,{}).get('enabled') and not available[n].get('deleted')]
            if not names:raise ValueError('Нет активных пользователей с профилями.')
            output=io.BytesIO()
            with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as archive:
                for n in names:
                    if not re.fullmatch(r'[A-Za-z0-9_-]{1,48}',n):raise ValueError('Некорректное имя профиля.')
                    for suffix in ('-UDP.ovpn','-TCP.ovpn','-credentials.txt'):
                        file=profiles/(n+suffix)
                        if not file.is_file():
                            if suffix=='-credentials.txt':continue
                            raise ValueError('Профили UDP/TCP отсутствуют. Восстановите профили на сервере.')
                        if file.is_symlink() or file.stat().st_size>1024*1024:raise ValueError('Некорректный файл профиля.')
                        archive.writestr(file.name,file.read_bytes())
            if output.tell()>12*1024*1024:raise ValueError('Архив слишком большой. Скачайте профили отдельных пользователей.')
            return {'archive':base64.b64encode(output.getvalue()).decode()}
    raise ValueError('Неизвестная операция.')

if 'DATA' in globals():
    try:print(json.dumps({'ok':True,'result':execute(DATA)},ensure_ascii=False))
    except ValueError as error:print(json.dumps({'ok':False,'error':str(error)},ensure_ascii=False))
    except Exception:print(json.dumps({'ok':False,'error':'Не удалось выполнить операцию. Проверьте установку VPNAI и права root на сервере.'},ensure_ascii=False))
