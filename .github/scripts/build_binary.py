#!/usr/bin/env python3
"""Build one native executable on the matching OS; only CI installs build dependencies."""
import argparse,os,pathlib,platform,re,shutil,subprocess,sys,tarfile,zipfile
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--version',required=True);parser.add_argument('--target',required=True)
a=parser.parse_args()
if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?',a.version):parser.error('Invalid version')
targets={'windows-x64':('Windows',{'amd64','x86_64'},'.exe'),'linux-x64':('Linux',{'amd64','x86_64'},''),'macos-arm64':('Darwin',{'arm64','aarch64'},'.command')}
if a.target not in targets:parser.error('Invalid target')
os_name,machines,extension=targets[a.target]
if platform.system()!=os_name or platform.machine().lower() not in machines:parser.error('Runner architecture does not match target')
root=pathlib.Path(__file__).resolve().parents[2];app=root/'app';output=root/'build/native';output.mkdir(parents=True,exist_ok=True)
name='VPNAI-'+a.version+'-'+a.target+extension
cmd=[sys.executable,'-m','PyInstaller','--noconfirm','--clean','--onefile','--console','--python-option','X utf8','--noupx','--name',name,'--distpath',str(output),'--workpath',str(root/'build/pyinstaller'),'--specpath',str(root/'build/spec'),'--paths',str(app),'--paths',str(app/'core'),'--hidden-import','engine']
for package in ('paramiko','cryptography','bcrypt','nacl'):cmd.extend(['--collect-all',package])
for source,destination in [(app/'core','core'),(app/'static','static'),(app/'admin_remote.py','.'),(app/'legacy_update_remote.py','.'),(app/'dns_remote.py','.'),(app/'dns_policy.py','.'),(app/'CHECKSUMS.json','.'),(root/'docs','docs'),(root/'readme.txt','.')]:cmd.extend(['--add-data',str(source)+':'+destination])
cmd.append(str(app/'app.py'));subprocess.run(cmd,check=True,cwd=root)
exe=output/name
if not exe.is_file():raise SystemExit('Executable missing: '+str(exe))
if os.name!='nt':exe.chmod(0o755)
print('BUILT:',exe,flush=True)

packages=root/'build/packages';packages.mkdir(parents=True,exist_ok=True)
if a.target.startswith('windows'):
    artifact=packages/exe.name;shutil.copy2(exe,artifact)
elif a.target.startswith('macos'):
    artifact=packages/(exe.name.removesuffix('.command')+'.zip')
    with zipfile.ZipFile(artifact,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:z.write(exe,exe.name)
else:
    artifact=packages/(exe.name+'.tar.gz')
    with tarfile.open(artifact,'w:gz') as tar:tar.add(exe,arcname=exe.name)
print('RELEASE ASSET:',artifact,flush=True)
