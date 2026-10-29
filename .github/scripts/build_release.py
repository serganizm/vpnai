#!/usr/bin/env python3
"""Build the portable application from the explicit, verified distribution manifest."""
import argparse,hashlib,json,pathlib,re,zipfile
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--version',required=True,help='Release tag, for example v0.1.3')
version=parser.parse_args().version
if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?',version):parser.error('Expected a version tag such as v0.1.3')
ROOT=pathlib.Path(__file__).resolve().parents[2]
manifest_file=ROOT/'app/CHECKSUMS.json'
manifest=json.loads(manifest_file.read_text())
files=[]
for name,digest in manifest.items():
    relative=pathlib.PurePosixPath(name)
    if relative.is_absolute() or '..' in relative.parts:raise SystemExit('Unsafe manifest path')
    path=ROOT.joinpath(*relative.parts)
    if path.is_symlink() or not path.is_file():raise SystemExit('Missing or symlinked distribution file: '+name)
    if hashlib.sha256(path.read_bytes()).hexdigest()!=digest:raise SystemExit('Checksum mismatch: '+name)
    files.append(path)
files.append(manifest_file)
output=ROOT/'build';output.mkdir(exist_ok=True)
archive=output/('VPNAI-'+version+'.zip')
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as package:
    for path in sorted(files):
        name='VPNAI/'+path.relative_to(ROOT).as_posix()
        if any(part.startswith('.') or part in ('__pycache__','__MACOSX') for part in pathlib.PurePosixPath(name).parts):raise SystemExit('Unwanted file: '+name)
        package.write(path,name)
with zipfile.ZipFile(archive) as package:
    if package.testzip() is not None:raise SystemExit('Invalid ZIP')
    expected={'app','docs','readme.txt','macos.command','linux.sh','windows.bat'}
    if {pathlib.PurePosixPath(name).parts[1] for name in package.namelist()}!=expected:raise SystemExit('Unexpected distribution layout')
    for name in package.namelist():
        relative=pathlib.PurePosixPath(name).relative_to('VPNAI')
        if relative.suffix.lower() in ('.md','.rst') and relative.parts[0]!='docs':raise SystemExit('Documentation outside docs: '+name)
    for name,digest in manifest.items():
        if hashlib.sha256(package.read('VPNAI/'+name)).hexdigest()!=digest:raise SystemExit('Packaged checksum mismatch: '+name)
    for path in (ROOT/'app/core/payload').rglob('*'):
        if path.is_file() and 'VPNAI/'+path.relative_to(ROOT).as_posix() not in package.namelist():raise SystemExit('Missing server payload: '+str(path))
    for name in ('macos.command','linux.sh'):
        if not (package.getinfo('VPNAI/'+name).external_attr>>16)&0o111:raise SystemExit('Launcher is not executable: '+name)
    count=len(package.namelist())
digest=hashlib.sha256(archive.read_bytes()).hexdigest()
(output/'SHA256SUMS.txt').write_text(digest+'  '+archive.name+'\n')
print('Verified portable ZIP:',archive.name,count,'files;',archive.stat().st_size,'bytes')
print('SHA256:',digest)
