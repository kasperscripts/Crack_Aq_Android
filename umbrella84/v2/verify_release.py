#!/usr/bin/env python3
"""Verify the published APK and the root script against pinned local builds."""
import argparse,base64,hashlib,json,re,struct,zipfile
from pathlib import Path

def sha(data):return hashlib.sha256(data).hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument('apk',type=Path);p.add_argument('root_script',type=Path);a=p.parse_args()
    directory=Path(__file__).resolve().parent
    apk=json.loads((directory/'apk-verification.json').read_text())
    root=json.loads((directory/'root-script-verification.json').read_text())
    assert a.apk.stat().st_size==apk['size']
    with a.apk.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==apk['sha256']
    with zipfile.ZipFile(a.apk) as z:
        assert len(z.namelist())==len(set(z.namelist())) and set(z.namelist())==set(apk['entry_sha256'])
        assert z.testzip() is None
        for name,expected in apk['entry_sha256'].items():
            data=z.read(name);assert sha(data)==expected,name
            assert b'umbreladlc' not in data.lower(),name
            assert 'umbreladlc'.encode('utf-16le') not in data.lower(),name
        assert b'@Icon_Crack' in z.read('classes7.dex')
        assert b'https://t.me/Icon_Crack' in z.read('lib/arm64-v8a/libumbrella.so')
    data=a.root_script.read_bytes();assert len(data)==root['size'] and sha(data)==root['sha256']
    text=data.decode()
    for name,marker in [('cfinject','CFESP_INJECTOR_PAYLOAD'),('libcfesp.so','CFESP_LIBRARY_PAYLOAD')]:
        pattern=r"base64 -d > \"\$RUNTIME/"+re.escape(name)+r"\" <<'"+marker+r"'\n(.*?)\n"+marker
        match=re.search(pattern,text,re.S);assert match,name
        payload=base64.b64decode(match[1]);expected=root['embedded'][name]
        assert len(payload)==expected['size'] and sha(payload)==expected['sha256']
        if name=='libcfesp.so':
            assert text.count(expected['sha256'])==2
            assert b'umbreladlc' not in payload.lower()
    print('Exact APK/root SHA-256, ZIP CRCs, every entry, root payloads and digest guards verified')

if __name__=='__main__':main()
