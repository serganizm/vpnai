"""Local DNS controller: explicit apply, pinned SSH and live revisions."""
import copy,ipaddress,json,pathlib,re
import backend
ROOT=pathlib.Path(__file__).resolve().parent
POLICY=(ROOT/'dns_policy.py').read_text().split("if __name__=='__main__':")[0]
REMOTE=POLICY+'\n'+(ROOT/'dns_remote.py').read_text()+'''\ntry:print(json.dumps({'ok':True,'result':execute(DATA)},ensure_ascii=False))
except ValueError as error:print(json.dumps({'ok':False,'error':str(error)},ensure_ascii=False))
'''
UNIT='''[Unit]
Description=VPNAI DNS policy routing
After=network-online.target ovpn-network.service ovpn-tcp-network.service
Wants=network-online.target ovpn-network.service ovpn-tcp-network.service
Before=openvpn-server@ru.service openvpn-server@ru-tcp.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/ovpn-dns-policy
ExecStop=/usr/local/sbin/ovpn-dns-policy clear
[Install]
WantedBy=multi-user.target
'''
PRESETS={'google':['8.8.8.8','8.8.4.4'],'cloudflare':['1.1.1.1','1.0.0.1'],'unchanged':[]}

def validate(data):
 if not isinstance(data,dict):raise backend.UserError('Некорректная настройка DNS.')
 provider=data.get('provider')
 if provider in PRESETS:servers=list(PRESETS[provider])
 elif provider=='custom':
  servers=data.get('servers')
  if not isinstance(servers,list) or not 1<=len(servers)<=2:raise backend.UserError('Укажите один или два публичных IPv4 DNS.')
 else:raise backend.UserError('Выберите провайдера DNS.')
 result=[]
 for value in servers:
  try:ip=ipaddress.ip_address(value) if isinstance(value,str) else None
  except ValueError:ip=None
  if ip is None or ip.version!=4 or not ip.is_global:raise backend.UserError('Для DNS нужны публичные IPv4-адреса.')
  if str(ip) in result:raise backend.UserError('DNS-адреса не должны повторяться.')
  result.append(str(ip))
 return {'provider':provider,'servers':result}

def remote(settings,role,operation,**data):
 ep=backend.make_remote(role,settings)
 try:
  ep.connect();ep.lock();return execute(ep,operation,**data)
 finally:ep.close()

def execute(ep,operation,**data):
 try:reply=json.loads(ep.python(REMOTE,dict(data,operation=operation)))
 except backend.UserError:raise
 except Exception:raise backend.UserError('Не удалось выполнить DNS-операцию. Проверьте сервер и повторите чтение настроек.') from None
 if not reply.get('ok'):raise backend.UserError(reply.get('error','Не удалось изменить DNS.'))
 return reply['result']

def dispatch(settings,operation,data):
 if operation=='dns-status':return remote(settings,'ru','read')
 chosen=validate(data)
 if any(ip in [settings[r]['host'] for r in ('ru','nl')] for ip in chosen['servers']):raise backend.UserError('DNS не должен совпадать с адресами этой пары VPN-серверов.')
 if operation=='dns-probe':return remote(settings,'nl','probe',servers=chosen['servers']) if chosen['servers'] else {'checks':[],'passed':True}
 if operation!='dns-apply':raise backend.UserError('Неизвестная DNS-операция.')
 if data.get('confirmed') is not True:raise backend.UserError('Подтвердите перезапуск OpenVPN и переподключение клиентов.')
 revision=data.get('revision','')
 if not isinstance(revision,str) or not re.fullmatch('[0-9a-f]{64}',revision):raise backend.UserError('Сначала считайте текущие DNS-настройки с сервера.')
 checked=remote(settings,'nl','probe',servers=chosen['servers']) if chosen['servers'] else {'passed':True}
 if not checked['passed']:raise backend.UserError('DNS недоступен с EU по UDP или TCP 53. Настройки не изменены.')
 return remote(settings,'ru','apply',**chosen,revision=revision,peer=settings['nl']['host'],helper=(ROOT/'dns_policy.py').read_text(),unit=UNIT)

def apply_install(chosen,ru,nl):
 chosen=validate(chosen)
 checked=execute(nl,'probe',servers=chosen['servers']) if chosen['servers'] else {'passed':True}
 if not checked['passed']:raise backend.UserError('DNS недоступен с EU. VPN установлен, но DNS не применён; выберите другой адрес в управлении.')
 current=execute(ru,'read')
 return execute(ru,'apply',**chosen,revision=current['revision'],peer=nl.host,helper=(ROOT/'dns_policy.py').read_text(),unit=UNIT)

def saved(ep):
 try:
  value=json.loads(ep.python("import pathlib,json; p=pathlib.Path('/etc/ovpn-routing/dns.json'); print(p.read_text() if p.exists() else 'null')"))
  return validate(value) if isinstance(value,dict) and value.get('version')==1 else None
 except (ValueError,backend.UserError):raise backend.UserError('Не удалось прочитать сохранённый DNS; проверьте настройки перед изменением установки.') from None

CAPTURE=r'''import pathlib,shlex,json,ipaddress
profiles={}
for name in ('ru','ru-tcp'):
 p=pathlib.Path('/etc/openvpn/server')/(name+'.conf')
 if not p.is_file():continue
 servers=[]
 for line in p.read_text().splitlines():
  f=shlex.split(line,comments=True)
  if len(f)==2 and f[0]=='push':
   fields=f[1].split()
   if fields[:2]==['dhcp-option','DNS'] and len(fields)==3:servers.append(str(ipaddress.IPv4Address(fields[2])))
 profiles[name]=servers
p=pathlib.Path('/etc/ovpn-routing/dns.json');old=json.loads(p.read_text()) if p.exists() else {}
managed=old.get('version')==1 and len(profiles)==2 and all(v==old.get('servers') for v in profiles.values())
print(json.dumps({'profiles':profiles,'managed':managed}))
'''
RESTORE_PUSH=r'''import pathlib,json
for name,servers in DATA['profiles'].items():
 if name not in ('ru','ru-tcp'):raise ValueError('Unexpected profile')
 p=pathlib.Path('/etc/openvpn/server')/(name+'.conf')
 if not p.is_file():continue
 text=p.read_text()
 if DATA['managed'] and servers:text+='\n# VPNAI DNS BEGIN\n'
 for ip in servers:
  text+='push "dhcp-option DNS '+ip+'"\n'
  if DATA['managed']:text+='push "route '+ip+' 255.255.255.255"\n'
 if DATA['managed'] and servers:text+='# VPNAI DNS END\n'
 tmp=p.with_name(p.name+'.dns-preserve');tmp.write_text(text);tmp.chmod(p.stat().st_mode&0o777);tmp.replace(p)
print('preserved')
'''
def capture(ep):
 try:
  result=json.loads(ep.python(CAPTURE))
  return result if isinstance(result,dict) and isinstance(result.get('profiles'),dict) else None
 except (ValueError,backend.UserError):raise backend.UserError('Не удалось прочитать действующие DNS перед обновлением. Настройки ещё не заменены.') from None

def preserve_push(ep,captured):
 if captured:ep.python(RESTORE_PUSH,captured)
