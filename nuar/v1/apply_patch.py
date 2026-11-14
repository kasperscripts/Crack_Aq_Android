"""Verify the original, then reconstruct the exact locally signed APK in place."""
import hashlib,json,struct,sys,zipfile
from pathlib import Path
import bsdiff4
apk=Path(sys.argv[1]);patch=Path(sys.argv[2])
with zipfile.ZipFile(patch) as z:
 manifest=json.loads(z.read('manifest.json'));delta=z.read('loader.bsdiff');tail=z.read('tail.bin')
assert manifest['format']=='nuar-exact-apk-v1'
assert apk.stat().st_size==manifest['source_size']
with apk.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==manifest['source_sha256']
assert hashlib.sha256(delta).hexdigest()==manifest['loader_patch_sha256'] and hashlib.sha256(tail).hexdigest()==manifest['tail_sha256']
with apk.open('r+b') as f:
 f.seek(manifest['loader']['data_offset']);old=f.read(manifest['loader']['compressed_size']);new=bsdiff4.patch(old,delta);assert len(old)==len(new)
 assert hashlib.sha256(new).hexdigest()==manifest['loader_compressed_sha256']
 f.seek(manifest['loader']['data_offset']);f.write(new);f.seek(manifest['loader']['header_offset']+14);f.write(struct.pack('<I',manifest['loader']['crc32']))
 f.seek(manifest['tail_offset']);f.write(tail);f.truncate()
assert apk.stat().st_size==manifest['target_size']
with apk.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==manifest['target_sha256']
print('PASS: exact signed APK reconstructed:',manifest['target_sha256'])
