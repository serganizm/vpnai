#!/usr/bin/env python3
"""Bundle a clean VPNAI source tree and Android-only UI adaptations."""
import argparse
import hashlib
import json
import pathlib
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent

EXPORT_JS = r'''
window.addEventListener('vpnai-session-ended', () => {
  if (window.VPNAIAndroid) window.VPNAIAndroid.sessionEnded();
});
async function vpnaiSaveBlob(blob, filename) {
  if (window.VPNAIAndroid) {
    if (blob.size > 64 * 1024 * 1024) throw Error('Архив больше 64 МиБ. Скачайте профили по отдельным пользователям.');
    const base64 = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onerror = () => reject(Error('Не удалось подготовить файл.'));
      reader.onload = () => resolve(String(reader.result).split(',')[1]);
      reader.readAsDataURL(blob);
    });
    window.VPNAIAndroid.saveFile(filename, blob.type, base64);
  } else {
    const url=URL.createObjectURL(blob), a=document.createElement('a');
    a.href=url; a.download=filename; a.click();
    setTimeout(()=>URL.revokeObjectURL(url),10000);
  }
}
'''

MOBILE_CSS = '''
/* Android layout: retain the existing views while fitting a phone. */
@media(max-width:600px){
  .repository-link{overflow-wrap:anywhere}
  .workspace-switch{width:100%}
  .workspace-switch button{padding-left:14px;padding-right:14px}
  .server-grid,.choice-grid,.choice-grid.three,.admin-grid{grid-template-columns:1fr!important}
  .metric-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}
  .quick-actions{grid-template-columns:1fr!important}
  .user-table-actions{flex-wrap:wrap;justify-content:flex-end;gap:10px}
  .admin-card{min-width:0}
  .admin-card-header{flex-wrap:wrap;gap:12px}
  .users-table{min-width:850px}
  input,select,textarea{font-size:16px!important}
}
'''

def prepare(source):
    files = {}
    for relative in ('app', 'docs'):
        for path in (source / relative).rglob('*'):
            if not path.is_file() or any(part.startswith('.') or part == '__pycache__' for part in path.relative_to(source).parts):
                continue
            if 'tests' in path.relative_to(source).parts or path.suffix == '.pyc':
                continue
            files[str(path.relative_to(source))] = path.read_bytes()
    files['readme.txt'] = (source / 'readme.txt').read_bytes()
    for ui in (ROOT / 'ui').iterdir():
        if ui.is_file(): files['app/static/' + ui.name] = ui.read_bytes()
    js = files['app/static/app.js'].decode()
    old = "const blob=await r.blob(),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=suffix==='report'?'vpn-report.json':'openvpn-all.zip';a.click();setTimeout(()=>URL.revokeObjectURL(url),10000);"
    new = "const blob=await r.blob();await vpnaiSaveBlob(blob,suffix==='report'?'vpn-report.json':'openvpn-all.zip');"
    assert js.count(old) == 1, 'Installation download handler changed'
    js = js.replace(old, new)
    old = "const link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download='openvpn-'+(target.dataset.exportName||'all')+'.zip';link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000);"
    new = "await vpnaiSaveBlob(blob,'openvpn-'+(target.dataset.exportName||'all')+'.zip');"
    assert js.count(old) == 1, 'Administration download handler changed'
    js = EXPORT_JS + js.replace(old, new)
    files['app/static/app.js'] = js.encode()
    html = files['app/static/index.html'].decode().replace('Только на этом компьютере', 'Только на этом телефоне')
    html = html.replace('Вкладку можно закрыть. Окно запуска приложения должно оставаться открытым.', 'Во время установки держите VPNAI открытым. Не завершайте приложение принудительно.')
    files['app/static/index.html'] = html.encode()
    if 'mobile-preview' not in html:
        files['app/static/style.css'] += MOBILE_CSS.encode()
    checksums = {name: hashlib.sha256(data).hexdigest() for name, data in files.items() if not name.endswith('CHECKSUMS.json')}
    files['app/CHECKSUMS.json'] = json.dumps(checksums, indent=2).encode()
    destination = ROOT / 'app/src/main/assets/payload.zip'
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED) as output:
        for name, data in sorted(files.items()):
            output.writestr(name, data)
    print(f'Bundled {len(files)} files: {destination}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=pathlib.Path)
    prepare(parser.parse_args().source.resolve())
