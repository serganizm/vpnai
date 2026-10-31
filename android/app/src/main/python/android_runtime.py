"""Android lifecycle adapter; the actual SSH operations remain in VPNAI."""
import hashlib
import json
import os
import pathlib
import sys
import threading
import time
import zipfile

_server = None
_thread = None

def start(files_dir, archive_path):
    global _server, _thread
    if _server is not None and _thread.is_alive():
        return 'http://127.0.0.1:%s/#%s' % (_server.server_port, _server.application.token)
    archive = pathlib.Path(archive_path)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()[:16]
    base = pathlib.Path(files_dir)
    home = base / 'home'
    home.mkdir(exist_ok=True)
    (home / '.ssh').mkdir(mode=0o700, exist_ok=True)
    os.environ['HOME'] = str(home)
    os.environ['VPNAI_ANDROID'] = '1'
    payload = base / ('payload-' + digest)
    if not (payload / '.ready').exists():
        payload.mkdir(exist_ok=True)
        with zipfile.ZipFile(archive) as source:
            for item in source.infolist():
                target = (payload / item.filename).resolve()
                if not target.is_relative_to(payload.resolve()):
                    raise ValueError('Invalid bundled path')
            source.extractall(payload)
        (payload / '.ready').touch()
    sys.path.insert(0, str(payload / 'app'))
    import app
    import paramiko
    # Fail visibly on startup if the SSH/native dependency stack cannot load.
    import cryptography.hazmat.bindings._rust
    import bcrypt
    import nacl.bindings
    _server = app.Server(('127.0.0.1', 0), app.Application())
    def serve():
        try:
            _server.serve_forever()
        finally:
            _server.application.close()
            _server.server_close()
    _thread = threading.Thread(target=serve, name='vpnai-http', daemon=True)
    _thread.start()
    def reap():
        while _thread.is_alive():
            time.sleep(5)
            with _server.application.lock:
                for job in _server.application.jobs.values():
                    with job.lock:
                        if job.artifact and time.time() >= job.expires:
                            job.artifact = None
    threading.Thread(target=reap, daemon=True).start()
    return 'http://127.0.0.1:%s/#%s' % (_server.server_port, _server.application.token)

def running():
    return bool(_thread and _thread.is_alive())

def busy():
    return bool(_server and any(job.status == 'running' for job in list(_server.application.jobs.values())))

def stop():
    if busy():
        return False
    if _server and running():
        _server.shutdown()
        _thread.join(timeout=10)
    return True

def offline_check():
    """Exercise the installed Android runtime without connecting to a VPS."""
    import urllib.request
    import urllib.error
    import bundled_check
    result = bundled_check.self_test()
    import dns_backend,legacy_update_remote,ssh_guard
    assert ssh_guard.LEASE_SECONDS == 45
    result['ssh_guard'] = True
    result['legacy_update'] = True
    assert dns_backend.validate({'provider':'google'})['servers'] == ['8.8.8.8','8.8.4.4']
    assert 'def rule_key(' in dns_backend.REMOTE
    result['dns_backend'] = True
    base = 'http://127.0.0.1:%s' % _server.server_port
    def request(path, token=True, data=None):
        headers = {'X-Local-Token': _server.application.token} if token else {}
        if data is not None:
            headers['Content-Type'] = 'application/json'
            data = json.dumps(data).encode()
        return urllib.request.urlopen(urllib.request.Request(base + path, data, headers), timeout=10)
    with request('/api/info') as response:
        assert json.load(response)['ssh_available']
    try:
        request('/api/info', token=False)
        raise AssertionError('API accepted missing token')
    except urllib.error.HTTPError as error:
        assert error.code == 403
    for path in ('/', '/style.css', '/app.js', '/help', '/docs/SETUP.md'):
        with request(path, token=False) as response:
            assert response.status == 200 and response.read()
    with request('/api/session', data={}) as response:
        assert json.load(response)['saved']
    with request('/api/ssh/aliases') as response:
        json.load(response)
    result['local_http'] = True
    result['api_token_required'] = True
    result['android'] = hasattr(sys, 'getandroidapilevel')
    return json.dumps(result)
