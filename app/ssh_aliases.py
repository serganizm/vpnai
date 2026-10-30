# -*- coding: utf-8 -*-
"""Read SSH aliases without executing config commands or opening private keys."""
import fnmatch, glob, ipaddress, os, pathlib, re, shlex, socket, sys
import backend

def config_paths(platform=None,environ=None,home=None):
    platform=platform or sys.platform;env=os.environ if environ is None else environ;home=pathlib.Path(home or pathlib.Path.home())
    if platform=='win32':
        return [pathlib.Path(env.get('USERPROFILE',str(home)))/'.ssh'/'config',pathlib.Path(env.get('PROGRAMDATA',r'C:\ProgramData'))/'ssh'/'ssh_config']
    return [home/'.ssh'/'config',pathlib.Path('/etc/ssh/ssh_config')]

def words(text):
    parser=shlex.shlex(text,posix=True);parser.whitespace_split=True;parser.commenters='#';parser.escape=''
    return list(parser)

def catalog(paths=None):
    paths=config_paths() if paths is None else [pathlib.Path(p) for p in paths]
    lines=[];warnings=[];read=set();total=0
    def expand(path,base,stack=()):
        nonlocal total
        path=pathlib.Path(path).expanduser()
        if len(stack)>=12 or path in stack:
            warnings.append('Циклический или слишком глубокий Include пропущен.');return
        if not path.is_file():return
        if len(read)>=128 or path.stat().st_size>1024*1024 or total>4*1024*1024:
            warnings.append('Достигнут лимит чтения SSH-конфигурации.');return
        try:content=path.read_text(encoding='utf-8-sig')
        except (OSError,UnicodeError):warnings.append('Не удалось прочитать SSH-конфигурацию: '+str(path));return
        read.add(path);total+=len(content.encode('utf-8'))
        for raw in content.splitlines():
            raw=raw.strip()
            if not raw or raw.startswith('#'):continue
            match=re.match(r'^([A-Za-z][\w-]*)\s*(?:=|\s)\s*(.*)$',raw)
            if not match:continue
            key=match[1].lower()
            try:values=words(match[2])
            except ValueError:warnings.append('Некорректная строка в '+str(path));continue
            if key=='include':
                for pattern in values:
                    pattern=os.path.expandvars(os.path.expanduser(pattern))
                    if not pathlib.Path(pattern).is_absolute():pattern=str(base/pattern)
                    for child in sorted(glob.glob(pattern)):expand(child,base,stack+(path,))
            else:lines.append((key,values))
    for path in paths:expand(path,path.parent)
    aliases=[]
    for key,values in lines:
        if key=='host':
            aliases.extend(v for v in values if v and not any(c in v for c in '*?!%') and not any(ord(c)<33 for c in v))
    has_match=any(key=='match' for key,_ in lines)
    if has_match:warnings.append('Match-блоки требуют ручного подключения; команды из SSH-конфига не выполняются.')
    result=[]
    for alias in sorted(set(aliases),key=str.casefold):
        options={};active=True
        for key,values in lines:
            if key=='host':
                positive=[v for v in values if not v.startswith('!')];negative=[v[1:] for v in values if v.startswith('!')]
                active=any(fnmatch.fnmatchcase(alias,v) for v in positive) and not any(fnmatch.fnmatchcase(alias,v) for v in negative)
            elif key=='match':active=False
            elif active and values and key not in options:options[key]=' '.join(values)
        host=options.get('hostname',alias).replace('%h',alias);user=options.get('user','root')
        key_path=options.get('identityfile','')
        for token,value in [('%d',str(pathlib.Path.home())),('%h',host),('%n',alias),('%r',user)]:key_path=key_path.replace(token,value)
        key_path=os.path.expandvars(os.path.expanduser(key_path))
        reason=''
        if has_match:reason='Есть Match-блоки: заполните подключение вручную.'
        if user!='root':reason='Администрирование VPNAI требует root; в алиасе указан '+user+'.'
        if any(options.get(k,'none').lower()!='none' for k in ('proxyjump','proxycommand','certificatefile')):reason='ProxyJump, ProxyCommand и SSH-сертификаты пока не поддерживаются.'
        try:port=int(options.get('port',22));assert 1<=port<=65535
        except (ValueError,AssertionError):port=22;reason='Некорректный SSH-порт в алиасе.'
        result.append({'alias':alias,'host':host,'port':port,'user':user,'key_path':key_path,'method':'local-key' if key_path and key_path.lower()!='none' else 'password','disabled':bool(reason),'reason':reason})
    return {'aliases':result,'paths':[str(p) for p in paths],'warnings':list(dict.fromkeys(warnings))}

def resolve_alias(alias):
    if not isinstance(alias,str):raise backend.UserError('Выберите SSH-алиас.')
    entry=next((item for item in catalog()['aliases'] if item['alias']==alias),None)
    if entry is None:raise backend.UserError('SSH-алиас больше не найден. Обновите список.')
    if entry['disabled']:raise backend.UserError(entry['reason'])
    host=entry['host']
    try:addresses=[str(ipaddress.ip_address(host))]
    except ValueError:
        if len(host)>253 or not re.fullmatch(r'[A-Za-z0-9_.-]+',host):raise backend.UserError('Некорректный HostName в SSH-алиасе.')
        try:addresses=sorted(set(row[4][0] for row in socket.getaddrinfo(host,entry['port'],socket.AF_INET,socket.SOCK_STREAM)))
        except OSError:raise backend.UserError('Не удалось определить IPv4 для SSH-алиаса.') from None
    addresses=[ip for ip in addresses if ipaddress.ip_address(ip).version==4 and ipaddress.ip_address(ip).is_global]
    if not addresses:raise backend.UserError('Для VPNAI нужен публичный IPv4. В алиасе другой адрес.')
    if len(addresses)>1:raise backend.UserError('Алиас имеет несколько IPv4. Введите нужный IP вручную.')
    return dict(entry,host=addresses[0])
