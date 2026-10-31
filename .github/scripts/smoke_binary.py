#!/usr/bin/env python3
"""Run only the downloaded executable, offline, without Python packages beside it."""
import argparse,json,pathlib,queue,re,shutil,subprocess,tempfile,threading,time,urllib.request
p=argparse.ArgumentParser();p.add_argument('--file');p.add_argument('--version');p.add_argument('--target');a=p.parse_args()
if a.file:exe=pathlib.Path(a.file).resolve()
else:
    extension='.exe' if a.target.startswith('windows') else '.command' if a.target.startswith('macos') else ''
    exe=pathlib.Path('build/native')/('VPNAI-'+a.version+'-'+a.target+extension)
    exe=exe.resolve()
with tempfile.TemporaryDirectory(prefix='vpnai-standalone-') as temp:
    # The standalone executable has no app directory or .venv next to it.
    path=pathlib.Path(temp)/exe.name;shutil.copy2(exe,path)
    if __import__('os').name!='nt':path.chmod(0o755)
    check=subprocess.run([str(path),'--self-test'],cwd=temp,capture_output=True,text=True,encoding='utf-8',timeout=90,check=False)
    if check.returncode:raise RuntimeError('Offline self-test failed: '+check.stdout+'\n'+check.stderr)
    result=json.loads(check.stdout.strip());assert result['standalone'] and result['ssh_available'] and result['native_crypto'] and result['core_files_verified']>20,result
    print('OFFLINE SELF-TEST:',json.dumps(result),flush=True)
    process=subprocess.Popen([str(path),'--no-browser','--port','0'],cwd=temp,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding='utf-8',errors='replace')
    lines=queue.Queue()
    def read():
        for line in process.stdout:lines.put(line)
    threading.Thread(target=read,daemon=True).start()
    try:
        deadline=time.monotonic()+60;url=None;log=[]
        while time.monotonic()<deadline:
            try:line=lines.get(timeout=1)
            except queue.Empty:
                if process.poll() is not None:raise RuntimeError('Standalone process exited: '+''.join(log))
                continue
            log.append(line);match=re.search(r'http://127\.0\.0\.1:[0-9]+/#[A-Za-z0-9_-]+',line)
            if match:url=match.group();break
        if not url:raise RuntimeError('No local application URL: '+''.join(log))
        base,token=url.split('#');headers={'X-Local-Token':token}
        def request(route,data=None):
            h=dict(headers)
            if data is not None:h['Content-Type']='application/json';data=json.dumps(data).encode()
            with urllib.request.urlopen(urllib.request.Request(base.rstrip('/')+route,data,headers=h),timeout=15) as response:return response.read()
        info=json.loads(request('/api/info'));assert info['ssh_available'] and info['standalone'],info
        assert b'serverCards' in request('/')
        assert request('/help')==request('/docs/readme.md')
        assert request('/readme.txt') and request('/docs/STANDALONE.md')
        assert request('/static/logo.jpg').startswith(b'\xff\xd8')
        session={'dns':{'provider':'cloudflare','servers':['1.1.1.1','1.0.0.1']},'ru':{'host':'8.8.8.8','password':'offline-fixture'},'nl':{'host':'9.9.9.9','password':'offline-fixture'}}
        assert json.loads(request('/api/session',session))['saved']
        assert json.loads(request('/api/session'))==session
        assert not json.loads(request('/api/info'))['running']
        assert not json.loads(request('/api/admin/status',{}))['connected']
        draft={'draft':{role:session[role] for role in ('ru','nl')},'revision':1}
        assert json.loads(request('/api/admin/save-connection-session',draft))['draft']==draft['draft']
        assert json.loads(request('/api/admin/connection-session',{}))['draft']==draft['draft']
        assert isinstance(json.loads(request('/api/ssh/aliases'))['aliases'],list)
        assert not json.loads(request('/api/info'))['install_connected']
        assert b'id="demo"' not in request('/')
        request('/api/exit',{})
        process.wait(timeout=30)
        assert process.returncode==0,process.returncode
        print('PASS: standalone HTTP UI, bundled SSH, embedded docs, in-memory session without SSH connections and clean exit',flush=True)
    finally:
        if process.poll() is None:
            if __import__('os').name=='nt':subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],capture_output=True)
            else:process.terminate()
            try:process.wait(timeout=15)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
