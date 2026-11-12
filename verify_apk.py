#!/usr/bin/env python3
"""Verify every preserved APK compressed stream against the source build."""
import argparse,hashlib,json,struct,zipfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('apk',type=Path);p.add_argument('--manifest',type=Path,default=Path('repack-verification.json'));p.add_argument('--native',type=Path,default=Path('native-patch.json'));p.add_argument('--report',type=Path,required=True);a=p.parse_args()
removed=[]
original=json.loads(a.manifest.read_text());native=json.loads(a.native.read_text());count=0
with zipfile.ZipFile(a.apk) as z,a.apk.open('rb') as f:
 for item in original['preserved_entries']:
  if item['name']=='stamp-cert-sha256' and item['name'] not in z.namelist():
   removed.append(item['name']);continue
  i=z.getinfo(item['name']);assert (i.file_size,i.compress_size,f'{i.CRC:08x}')==(item['size'],item['compressed_size'],item['crc32'])
  f.seek(i.header_offset);h=f.read(30);n,x=struct.unpack_from('<HH',h,26);f.seek(n+x,1);remaining=i.compress_size;digest=hashlib.sha256()
  while remaining:
   b=f.read(min(16*1024*1024,remaining));assert b;remaining-=len(b);digest.update(b)
  assert digest.hexdigest()==item['compressed_sha256'],i.filename;count+=1
 assert hashlib.sha256(z.read('lib/arm64-v8a/libAQR.so')).hexdigest()==native['patched_sha256']
 assert len(z.infolist())==count+1
with a.apk.open('rb') as f:sha=hashlib.file_digest(f,'sha256').hexdigest()
report={'apk_size':a.apk.stat().st_size,'apk_sha256':sha,'preserved_compressed_entries_verified':count,'changed_entry':'lib/arm64-v8a/libAQR.so','obsolete_source_stamp_removed_by_signer':removed,'manifest_dex_game_assets_and_other_native_libraries_preserved':True}
a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
