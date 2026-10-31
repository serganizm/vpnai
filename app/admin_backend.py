# -*- coding: utf-8 -*-
"""Administration service. Reuses the installer's pinned SSH transport."""
import base64, contextlib, copy, ipaddress, json, pathlib, re, threading
import backend

REMOTE=(pathlib.Path(__file__).with_name('admin_remote.py')).read_text()

def username(value,optional=False):
    if optional and value=='':return value
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,48}',value):raise backend.UserError('Логин: латинские буквы, цифры, _ или -, до 48 символов.')
    return value

def comment(value):
    if not isinstance(value,str) or len(value)>200 or any(ord(c)<32 or ord(c)==127 for c in value):raise backend.UserError('Комментарий: до 200 символов, без управляющих знаков.')
    return value

class AdminService:
    def __init__(self,application):self.app=application;self.settings=None;self.lock=threading.RLock();self.connected=False;self.draft={};self.draft_revision=0
    def close(self):
        with self.lock:
            if self.settings:
                for role in ('ru','nl'):self.settings[role].clear()
            self.settings=None;self.connected=False
    def connection_session(self,data=None):
        with self.app.lock,self.lock:
            if self.app.stopping:raise backend.UserError('Приложение завершает работу.')
            if data is not None:
                if not isinstance(data,dict):raise backend.UserError('Ожидается объект данных сеанса.')
                if 'draft' in data:
                    revision=data.get('revision')
                    if type(revision) is not int or not 0<=revision<=2**53-1:raise backend.UserError('Некорректная версия данных сеанса.')
                    payload=data['draft']
                else:revision=self.draft_revision+1;payload=data
                saved=backend.session_payload(payload)
                if revision>=self.draft_revision:
                    self.draft={role:dict(saved.get(role,{})) for role in ('ru','nl')};self.draft_revision=revision
            if not self.draft and self.settings:
                self.draft={role:{key:value for key,value in self.settings[role].items() if key!='fingerprint'} for role in ('ru','nl')}
            return {'draft':copy.deepcopy(self.draft),'revision':self.draft_revision}
    def remote(self,role,operation,settings=None,**data):
        current=settings or self.settings
        if current is None:raise backend.UserError('Сначала подключитесь к серверам.')
        ep=backend.Remote(role,copy.deepcopy(current[role]))
        try:
            ep.connect();ep.lock();answer=json.loads(ep.python(REMOTE,dict(data,operation=operation)))
            if not answer.get('ok'):raise backend.UserError(answer.get('error','Ошибка сервера.'))
            return answer['result']
        except backend.UserError:raise
        except Exception:raise backend.UserError('Не удалось получить ответ сервера. Проверьте SSH и наличие Python 3.') from None
        finally:ep.close()
    def connect(self,data):
        self.connection_session(data)
        settings=backend.validate(dict(data,action='check'))
        for role,pin in self.app.trust.trusted(settings).items():settings[role]['fingerprint']=pin
        # Do not retain rejected credentials or replace a good connection on partial failure.
        self.remote('ru','overview',settings=settings,expected_peer=settings['nl']['host'])
        for role in ('ru','nl'):self.remote(role,'metrics',settings=settings)
        self.close();self.settings=settings;self.connected=True
        return self.snapshot()
    def snapshot(self):
        if not self.settings:return {'connected':False,'users':[],'sessions':[],'servers':{},'warnings':[]}
        try:
            overview=self.remote('ru','overview',expected_peer=self.settings['nl']['host']);servers={};warnings=overview.get('warnings',[])
            for role in ('ru','nl'):
                try:servers[role]=dict(self.remote(role,'metrics'),host=self.settings[role]['host'],available=True)
                except backend.UserError:
                    servers[role]={'host':self.settings[role]['host'],'available':False};warnings.append('Нет связи с '+('российским' if role=='ru' else 'зарубежным')+' сервером.')
            self.connected=all(s['available'] for s in servers.values())
            return dict(overview,connected=self.connected,servers=servers,warnings=warnings)
        except Exception:self.connected=False;raise
    def dispatch(self,operation,data):
        if not isinstance(data,dict):raise backend.UserError('Ожидается JSON-объект.')
        if operation=='connection-session':return self.connection_session()
        if operation=='save-connection-session':return self.connection_session(data)
        with self.app.lock,self.lock:
            if self.app.stopping or any(j.status=='running' for j in self.app.jobs.values()):raise backend.UserError('Дождитесь завершения текущей установки.')
            if operation=='connect':return self.connect(data)
            if operation=='disconnect':self.close();return {'connected':False}
            if operation=='status':return self.snapshot()
            if not self.settings:raise backend.UserError('Сначала подключитесь к серверам.')
            if operation in ('dns-status','dns-probe','dns-apply'):
                import dns_backend
                return dns_backend.dispatch(self.settings,operation,data)
            if operation in ('create','update','delete','credentials'):
                name=username(data.get('name'));request={'name':name}
                if operation in ('create','update'):request['comment']=comment(data.get('comment',''))
                if operation=='update':
                    password=data.get('password','')
                    if not isinstance(password,str) or (password and (not 8<=len(password)<=256 or any(c in password for c in '\r\n\x00'))):raise backend.UserError('Пароль: 8–256 символов, без перевода строки.')
                    request['password']=password
                if operation=='delete' and data.get('confirmation')!=name:raise backend.UserError('Для удаления введите логин пользователя.')
                return self.remote('ru',operation,**request)
            if operation in ('profiles','link'):return self.remote('ru',operation,name=username(data.get('name',''),optional=True))
            if operation=='routes':return self.remote('ru','routes')
            if operation=='route-change':
                if data.get('kind') not in ('ru','eu') or data.get('action') not in ('add','remove'):raise backend.UserError('Некорректное действие со списком.')
                try:network=ipaddress.ip_network(data.get('cidr',''),strict=False)
                except ValueError:raise backend.UserError('Укажите IPv4 или CIDR.') from None
                if network.version!=4 or not network.is_global or network.prefixlen<4:raise backend.UserError('Нужен публичный IPv4 или CIDR.')
                if data['kind']=='eu' and any(ipaddress.ip_address(self.settings[r]['host']) in network for r in ('ru','nl')):raise backend.UserError('RU-EU не должен включать адреса самих серверов.')
                return self.remote('ru',operation,kind=data['kind'],action=data['action'],cidr=str(network))
            if operation=='iplist-update':return self.remote('ru',operation)
            raise backend.UserError('Неизвестная операция администрирования.')
