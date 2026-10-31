"""Offline checks for the standalone runtime; never contacts servers."""
import json,pathlib,sys
import backend

def self_test():
    import ssl,bcrypt,nacl.signing
    import legacy_update,dns_backend,ssh_guard
    assert 'def execute(' in legacy_update.REMOTE
    assert ssh_guard.LEASE_SECONDS == 45
    assert dns_backend.validate({'provider':'google'})['servers'] == ['8.8.8.8','8.8.4.4']
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    pm=backend.get_paramiko()
    pm.RSAKey.generate(2048)
    key=nacl.signing.SigningKey.generate();message=b'VPNAI offline self-test'
    assert key.verify_key.verify(key.sign(message))==message
    aes=AESGCM(AESGCM.generate_key(bit_length=128));nonce=b'0'*12
    assert aes.decrypt(nonce,aes.encrypt(nonce,message,None),None)==message
    assert len(bcrypt.kdf(password=b'VPNAI-test',salt=b'VPNAI-offline-salt',desired_key_bytes=32,rounds=50))==32
    root=pathlib.Path(__file__).resolve().parent
    manifest=json.loads((root/'CHECKSUMS.json').read_text())
    import hashlib
    count=0
    for name,digest in manifest.items():
        if not name.startswith('app/core/'):continue
        path=root/name[len('app/'):]
        assert path.is_file(),name
        assert hashlib.sha256(path.read_bytes()).hexdigest()==digest,name
        count+=1
    for name in ('index.html','app.js','style.css'):assert (root/'static'/name).is_file()
    assert ((root if getattr(sys,'frozen',False) else root.parent)/'docs/SETUP.md').is_file()
    return {'standalone':bool(getattr(sys,'frozen',False)),'ssh_available':True,'paramiko':pm.__version__,'native_crypto':True,'core_files_verified':count,'legacy_update':True,'ssh_guard':True,'dns_backend':True,'openssl':ssl.OPENSSL_VERSION}
