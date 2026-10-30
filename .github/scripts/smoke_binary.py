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
    process=subprocess.Popen([str(path),'--no-browser'],cwd=temp,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding='utf-8',errors='replace')
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
        assert request('/help') and request('/docs/STANDALONE.md')
        job_id=json.loads(request('/api/jobs',{'demo':True,'action':'install'}))['id']
        for _ in range(50):
            job=json.loads(request('/api/jobs/'+job_id))
            if job['status']!='running':break
            time.sleep(.25)
        assert job['status']=='success',job
        archive=request('/api/jobs/'+job_id+'/download');assert archive[:2]==b'PK'
        request('/api/exit',{})
        process.wait(timeout=30)
        assert process.returncode==0,process.returncode
        print('PASS: standalone HTTP UI, bundled SSH, embedded docs, offline demo ZIP and clean exit',flush=True)
    finally:
        if process.poll() is None:
            if __import__('os').name=='nt':subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],capture_output=True)
            else:process.terminate()
            try:process.wait(timeout=15)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
