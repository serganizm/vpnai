#!/usr/bin/env python3
"""OpenVPN local web installer. Demo mode needs only Python 3.9+."""
import argparse,contextlib,json,pathlib,secrets,socket,threading,time,urllib.parse,webbrowser,sys
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import backend
from ssh_trust import TrustStore
ROOT=pathlib.Path(__file__).resolve().parent

def local_platform():
    return 'windows' if sys.platform=='win32' else 'macos' if sys.platform=='darwin' else 'linux'

class Application:
    def __init__(self,trust_path=None):self.token=secrets.token_urlsafe(32);self.jobs={};self.lock=threading.RLock();self.trust=TrustStore(trust_path)
    def start(self,data):
        settings=backend.validate(data)
        if not settings['demo']:
            for role,pin in self.trust.trusted(settings).items():settings[role]['fingerprint']=pin
        with self.lock:
            if any(j.status=='running' for j in self.jobs.values()):raise backend.UserError('Дождитесь завершения текущей операции или остановите её.')
            # Expire credential-bearing archives in memory.
            for j in self.jobs.values():j.artifact=None
            job=backend.Job(settings);self.jobs[job.id]=job
            while len(self.jobs)>20:self.jobs.pop(next(iter(self.jobs)))
            threading.Thread(target=job.run,name='vpn-operation',daemon=True).start();return job

class Handler(BaseHTTPRequestHandler):
    server_version='LocalInstaller';sys_version=''
    def log_message(self,*args):pass
    def allowed(self):
        host=self.headers.get('Host','')
        expected={f'127.0.0.1:{self.server.server_port}',f'localhost:{self.server.server_port}'}
        if host not in expected:return False
        origin=self.headers.get('Origin')
        return not origin or origin in {'http://'+h for h in expected}
    def authorized(self):return self.allowed() and secrets.compare_digest(self.headers.get('X-Local-Token',''),self.server.application.token)
    def send(self,status,body,kind='application/json; charset=utf-8',filename=None):
        raw=json.dumps(body,ensure_ascii=False).encode() if isinstance(body,(dict,list)) else body
        self.send_response(status);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(raw)))
        self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if filename:self.send_header('Content-Disposition','attachment; filename="'+filename+'"')
        self.end_headers()
        with contextlib.suppress(BrokenPipeError,ConnectionResetError):self.wfile.write(raw)
    def do_GET(self):
        path=urllib.parse.urlsplit(self.path).path
        if not self.allowed():self.send(403,{'error':'Доступ разрешён только с локального адреса.'});return
        static={'/':'index.html','/style.css':'style.css','/app.js':'app.js'}
        if path in static:
            p=ROOT/'static'/static[path];mime={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8'}[p.suffix]
            self.send(200,p.read_bytes(),mime);return
        if path=='/help':
            self.send(200,(ROOT/'readme.txt' if getattr(sys,'frozen',False) else ROOT.parent/'readme.txt').read_bytes(),'text/plain; charset=utf-8');return
        if path.startswith('/docs/') and path[len('/docs/'):] in {'SETUP.md','readme.md','SSH_TRUST.md','STANDALONE.md','TEST_REPORT.md','ARCHITECTURE.md','RELEASE_NOTES.md'}:
            folder=ROOT/'docs' if getattr(sys,'frozen',False) else ROOT.parent/'docs'
            p=folder/path[len('/docs/'):]
            if p.is_file():self.send(200,p.read_bytes(),'text/plain; charset=utf-8');return
        if not self.authorized():self.send(403,{'error':'Откройте адрес из окна запуска приложения.'});return
        if path=='/api/info':
            try:backend.get_paramiko();ssh=True
            except backend.UserError:ssh=False
            self.send(200,{'platform':local_platform(),'ssh_available':ssh,'standalone':bool(getattr(sys,'frozen',False)),'running':[j.id for j in self.server.application.jobs.values() if j.status=='running']});return
        pieces=path.strip('/').split('/')
        if len(pieces) in (3,4) and pieces[:2]==['api','jobs']:
            job=self.server.application.jobs.get(pieces[2])
            if job is None:self.send(404,{'error':'Операция не найдена.'});return
            if len(pieces)==3:self.send(200,job.public());return
            if pieces[3]=='report':self.send(200,{'status':job.status,'report':job.report,'events':job.events},filename='vpn-report.json');return
            if pieces[3]=='download':
                with job.lock:
                    if not job.artifact or time.time()>=job.expires:job.artifact=None;self.send(410,{'error':'Архив больше не доступен. Профили сохранены на российском сервере.'});return
                    artifact=job.artifact
                self.send(200,artifact,'application/zip','DEMO-preview.zip' if job.report.get('demo') else 'OpenVPN-profiles.zip');return
        self.send(404,{'error':'Не найдено.'})
    def do_POST(self):
        if not self.authorized():self.send(403,{'error':'Нет доступа.'});return
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0<length<=1024*1024:raise backend.UserError('Некорректный размер запроса.')
            if self.headers.get_content_type()!='application/json':raise backend.UserError('Нужен JSON-запрос.')
            data=json.loads(self.rfile.read(length));path=urllib.parse.urlsplit(self.path).path
            if path=='/api/ssh-command':
                self.send(200,backend.ssh_copy_command(data.get('host',''),data.get('port',22),data.get('platform',local_platform()),data.get('key_path','~/.ssh/id_ed25519')));return
            if path=='/api/ssh/prepare':
                settings=backend.validate(data)
                if settings['demo']:raise backend.UserError('Демонстрация не требует SSH-доверия.')
                pins=backend.fingerprints(settings)
                self.send(200,self.server.application.trust.prepare(settings,pins));return
            if path=='/api/ssh/confirm':
                if data.get('accept') is not True:raise backend.UserError('Доверие SSH не подтверждено.')
                self.send(200,self.server.application.trust.confirm(data.get('confirmation_token')));return
            if path=='/api/fingerprints':
                settings=backend.validate(data)
                if settings['demo']:result={'ru':'DEMO: fingerprint not used','nl':'DEMO: fingerprint not used'}
                else:result=backend.fingerprints(settings)
                self.send(200,result);return
            if path=='/api/jobs':job=self.server.application.start(data);self.send(202,{'id':job.id});return
            pieces=path.strip('/').split('/')
            if len(pieces)==4 and pieces[:2]==['api','jobs'] and pieces[3]=='cancel':
                job=self.server.application.jobs.get(pieces[2])
                if not job:raise backend.UserError('Операция не найдена.')
                job.cancel.set();self.send(200,{'message':'Остановка запрошена. Текущая серверная команда сначала завершится.'});return
            self.send(404,{'error':'Не найдено.'})
        except (backend.UserError,ValueError,TypeError) as e:self.send(400,{'error':str(e)})
        except Exception:self.send(400,{'error':'Не удалось выполнить запрос. Проверьте SSH-доступ и установленные компоненты.'})

class Server(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,application):self.application=application;super().__init__(address,Handler)

def main():
    for stream in (sys.stdout,sys.stderr):
        if hasattr(stream,'reconfigure'):stream.reconfigure(encoding='utf-8',errors='replace')
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--self-test',action='store_true');parser.add_argument('--port',type=int,default=0);parser.add_argument('--no-browser',action='store_true');args=parser.parse_args()
    if args.self_test:
        from bundled_check import self_test
        print(json.dumps(self_test()),flush=True);return
    app=Application();server=Server(('127.0.0.1',args.port),app)
    url=f'http://127.0.0.1:{server.server_port}/#'+app.token
    print('\nVPNAI · локальный установщик\n\n'+url+'\n\nНе закрывайте это окно во время операции. Для выхода: Ctrl+C.\n',flush=True)
    if not args.no_browser:webbrowser.open(url)
    # Delete expiring archives even when nobody polls the UI.
    def reap():
        while True:
            time.sleep(5)
            with app.lock:
                for job in app.jobs.values():
                    with job.lock:
                        if job.artifact and time.time()>=job.expires:job.artifact=None
    threading.Thread(target=reap,daemon=True).start()
    try:server.serve_forever()
    except KeyboardInterrupt:
        active=[j for j in app.jobs.values() if j.status=='running']
        if active:
            print('Ожидается безопасная остановка операции. Не завершайте процесс принудительно.',flush=True)
            for job in active:job.cancel.set()
            while any(j.status=='running' for j in active):time.sleep(.2)
    finally:server.server_close()
if __name__=='__main__':main()
