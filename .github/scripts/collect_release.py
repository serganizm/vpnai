"""Collect verified native builds and the locally signed Android build."""
import hashlib,io,json,os,pathlib,shutil,subprocess,sys,zipfile
root=pathlib.Path(__file__).resolve().parents[2];version=os.environ['RELEASE_TAG'];out=root/'build/release';out.mkdir(parents=True,exist_ok=True)
names=[f'VPNAI-{version}-android-arm64.apk',f'VPNAI-{version}-macos-arm64.zip',f'VPNAI-{version}-linux-x64.tar.gz',f'VPNAI-{version}-windows-x64.exe']
apk=root/'.github/release-input'/names[0];proof=json.loads((apk.parent/'android-verification.json').read_text())
assert hashlib.sha256(apk.read_bytes()).hexdigest()==proof['sha256'],'Android artifact differs from tested file'
assert proof['version']==version and proof['instrumentation_passed'] and proof['lint_passed'] and proof['connection_limits_passed']
# Rebuild the expected payload from tagged source, then compare every file to APK.
subprocess.run([sys.executable,str(root/'android/prepare_payload.py'),str(root)],check=True)
with zipfile.ZipFile(apk) as app,zipfile.ZipFile(root/'android/app/src/main/assets/payload.zip') as expected:
 with zipfile.ZipFile(io.BytesIO(app.read('assets/payload.zip'))) as actual:
  assert set(actual.namelist())==set(expected.namelist()),'APK payload file list differs'
  for name in expected.namelist():
   if name=='app/CHECKSUMS.json':
    assert json.loads(actual.read(name))==json.loads(expected.read(name)),'APK manifest differs'
   else:assert actual.read(name)==expected.read(name),'APK source mismatch: '+name
for name in names:
 p=apk if name.endswith('.apk') else root/'build/packages'/name
 if not p.is_file():raise SystemExit('Missing tested package: '+name)
 shutil.copy2(p,out/name)
source=root/f'build/VPNAI-source-{version}.zip';shutil.copy2(source,out/source.name)
# One extra archive contains the four ready-to-run platform packages.
combined=out/f'VPNAI-{version}-all-platforms.zip'
with zipfile.ZipFile(combined,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
 for name in names:archive.write(out/name,name)
 archive.writestr('readme.txt','VPNAI '+version+'\nAndroid ARM64: .apk\nmacOS Apple Silicon: .zip\nLinux x64: .tar.gz\nWindows x64: .exe\nDesktop applications bundle Python and SSH.\n')
with zipfile.ZipFile(combined) as archive:assert archive.testzip() is None
(out/'SHA256SUMS.txt').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(out.iterdir()) if p.name!='SHA256SUMS.txt'))
print('Verified release files:',*[p.name for p in sorted(out.iterdir())],sep='\n')

# Release pages resolve relative documentation links outside the source tree.
notes=(root/'docs/RELEASE_NOTES.md').read_text()
for name in ('LOCAL_LEGACY.md','DNS.md','CONNECTION_LIMITS.md'):
 notes=notes.replace('('+name+')','(https://github.com/'+os.environ.get('GITHUB_REPOSITORY','serganizm/vpnai')+'/blob/'+version+'/docs/'+name+')')
(root/'build/release-notes.md').write_text(notes)
