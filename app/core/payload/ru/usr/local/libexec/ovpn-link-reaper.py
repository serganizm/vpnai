#!/usr/bin/python3
import pathlib,json,time
root=pathlib.Path('/var/lib/ovpn-links')
while True:
 for p in root.glob('*.json'):
  try:
   if json.loads(p.read_text())['expires']<=time.time():p.unlink(missing_ok=True)
  except (FileNotFoundError,PermissionError,ValueError,KeyError):pass
 time.sleep(1)
