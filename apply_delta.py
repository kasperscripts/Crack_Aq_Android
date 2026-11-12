#!/usr/bin/env python3
"""Reconstruct and verify an exact signed APK; signing keys are never uploaded."""
import argparse,hashlib,json,zipfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('patch',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
assert a.source.resolve()!=a.output.resolve() and not a.output.exists()
with zipfile.ZipFile(a.patch) as z:
 assert set(z.namelist())=={'manifest.json','literal.bin'};manifest=json.loads(z.read('manifest.json'));literal=z.read('literal.bin')
assert manifest['format']==1 and hashlib.sha256(literal).hexdigest()==manifest['literal_sha256']
assert a.source.stat().st_size==manifest['source_size']
with a.source.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==manifest['source_sha256']
partial=a.output.with_suffix(a.output.suffix+'.partial');digest=hashlib.sha256();written=0
with a.source.open('rb') as src,partial.open('wb') as out:
 for kind,offset,size in manifest['commands']:
  assert kind in ['copy','data'] and offset>=0 and size>=0
  if kind=='data':
   assert offset+size<=len(literal);data=literal[offset:offset+size];out.write(data);digest.update(data);written+=len(data)
  else:
   assert offset+size<=manifest['source_size'];src.seek(offset)
   while size:
    data=src.read(min(size,16*1024*1024));assert data;out.write(data);digest.update(data);written+=len(data);size-=len(data)
assert written==manifest['target_size'] and digest.hexdigest()==manifest['target_sha256']
partial.rename(a.output);print('PASS: exact signed APK reconstructed, SHA-256',digest.hexdigest())
