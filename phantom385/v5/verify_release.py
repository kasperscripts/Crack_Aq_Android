#!/usr/bin/env python3
import argparse,hashlib,json,zipfile
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('apk',type=Path);args=parser.parse_args()
report=json.loads((Path(__file__).parent/'release-verification.json').read_text())
assert args.apk.stat().st_size==report['size']
assert hashlib.sha256(args.apk.read_bytes()).hexdigest()==report['sha256']
with zipfile.ZipFile(args.apk) as archive:
    assert archive.testzip() is None
    assert len(archive.namelist())==len(set(archive.namelist()))
    assert set(archive.namelist())==set(report['entry_sha256'])
    for name,expected in report['entry_sha256'].items():
        assert hashlib.sha256(archive.read(name)).hexdigest()==expected,name
    assert b'@Icon_Crack' in archive.read('classes.dex')
    assert b'PH-1D-' not in archive.read('classes.dex')
print('Exact APK SHA-256, ZIP CRCs, entry hashes and launcher branding verified')
