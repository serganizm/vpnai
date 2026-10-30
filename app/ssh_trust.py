"""Local SSH public-key trust, never credentials or private keys."""
import json,os,pathlib,re,secrets,tempfile,threading,time
from backend import UserError
PIN=re.compile(r'SHA256:[A-Za-z0-9+/]{43}')

class TrustStore:
    def __init__(self,path=None,persistent=True):
        self.path=(pathlib.Path(path) if path else pathlib.Path.home()/'.vpnai'/'ssh-hosts.json') if persistent else None
        self.memory={}
        self.lock=threading.RLock();self.pending={}
    def clear(self):
        with self.lock:self.memory.clear();self.pending.clear()
    def read(self):
        if self.path is None:return dict(self.memory)
        if not self.path.exists():return {}
        try:
            data=json.loads(self.path.read_text(encoding='utf-8'))
            if not isinstance(data,dict) or any(not isinstance(k,str) or not isinstance(v,str) or not PIN.fullmatch(v) for k,v in data.items()):raise ValueError()
            return data
        except (OSError,ValueError,UnicodeError):raise UserError('Не удалось прочитать локальную базу SSH-доверия ~/.vpnai/ssh-hosts.json. Проверка ключей не отключалась; восстановите корректный файл.') from None
    @staticmethod
    def identity(server):return server['host']+':'+str(server['port'])
    def trusted(self,settings):
        with self.lock:
            known=self.read();pins={}
            for role in ('ru','nl'):
                pin=known.get(self.identity(settings[role]))
                if not pin:raise UserError('Сначала выполните автоматическое получение и подтверждение SSH-ключей.')
                supplied=settings[role].get('fingerprint')
                if supplied and not secrets.compare_digest(pin,supplied):raise UserError('SSH-ключ запроса отличается от сохранённого. Подключение остановлено.')
                pins[role]=pin
            return pins
    def prepare(self,settings,pins):
        with self.lock:
            known=self.read();servers=[]
            for role in ('ru','nl'):
                server=settings[role];identity=self.identity(server);pin=pins[role]
                if not isinstance(pin,str) or not PIN.fullmatch(pin):raise UserError('Сервер вернул некорректный SSH-отпечаток.')
                previous=known.get(identity)
                if previous and not secrets.compare_digest(previous,pin):
                    raise UserError('SSH-ключ изменился: '+('российский' if role=='ru' else 'зарубежный')+' сервер '+identity+'. Пароль не передавался. Если сервер переустановлен, независимо сверьте новый ключ; автоматическая замена доверенного ключа запрещена.')
                servers.append({'role':role,'host':server['host'],'port':server['port'],'fingerprint':pin,'known':bool(previous)})
            now=time.time();self.pending={k:v for k,v in self.pending.items() if v['expires']>now}
            unknown=[s for s in servers if not s['known']]
            token=None
            if unknown:
                if len(self.pending)>=20:self.pending.pop(next(iter(self.pending)))
                token=secrets.token_urlsafe(24);self.pending[token]={'expires':now+300,'servers':servers}
            return {'confirmation_required':bool(unknown),'confirmation_token':token,'servers':servers,'fingerprints':dict(pins)}
    def confirm(self,token):
        with self.lock:
            candidate=self.pending.pop(token,None) if isinstance(token,str) else None
            if not candidate or candidate['expires']<=time.time():raise UserError('Подтверждение SSH-ключей истекло. Запустите операцию ещё раз для автоматического получения ключей.')
            known=self.read()
            for server in candidate['servers']:
                identity=self.identity(server);old=known.get(identity)
                if old and not secrets.compare_digest(old,server['fingerprint']):raise UserError('SSH-ключ уже изменён в базе доверия. Подключение остановлено.')
                known[identity]=server['fingerprint']
            if self.path is None:
                self.memory=dict(known)
                return {'fingerprints':{s['role']:s['fingerprint'] for s in candidate['servers']}}
            temp=None
            try:
                self.path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=self.path.parent,prefix='.ssh-hosts-',delete=False) as f:
                    temp=f.name
                    if os.name!='nt':os.chmod(temp,0o600)
                    json.dump(known,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
                os.replace(temp,self.path);temp=None
            except OSError:raise UserError('Не удалось сохранить локальное доверие SSH. Операция не запускалась; проверьте доступ к ~/.vpnai/.') from None
            finally:
                if temp:
                    try:os.unlink(temp)
                    except OSError:pass
            return {'fingerprints':{s['role']:s['fingerprint'] for s in candidate['servers']}}
