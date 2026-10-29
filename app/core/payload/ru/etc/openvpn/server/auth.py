#!/usr/bin/python3
import sys,json,hashlib,hmac,os
try:
 u,p=open(sys.argv[1]).read().splitlines()[:2]
 users=json.load(open('/etc/openvpn/server/users.json'));r=users[u]
 ok=r.get('enabled',False) and os.environ.get('common_name')==u and hmac.compare_digest(hashlib.pbkdf2_hmac('sha256',p.encode(),bytes.fromhex(r['salt']),300000).hex(),r['hash'])
 sys.exit(0 if ok else 1)
except Exception:sys.exit(1)
