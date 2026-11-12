#!/usr/bin/env python3
"""Package an exact signed APK update using unchanged compressed entry streams."""
import argparse,hashlib,json,struct,zipfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('target',type=Path);p.add_argument('source_map',type=Path);p.add_argument('output',type=Path);p.add_argument('--target-report',type=Path,required=True);a=p.parse_args()
source=json.loads(a.source_map.read_text());target=json.loads(a.target_report.read_text());literal=bytearray();commands=[];cursor=0
def add(data):
 if data:commands.append(['data',len(literal),len(data)]);literal.extend(data)
with a.target.open('rb') as f,zipfile.ZipFile(a.target) as z:
 for i in sorted(z.infolist(),key=lambda i:i.header_offset):
  f.seek(i.header_offset);header=f.read(30);n,x=struct.unpack_from('<HH',header,26);start=i.header_offset+30+n+x
  f.seek(cursor);add(f.read(start-cursor))
  old=source['entries'][i.filename]
  if i.filename=='lib/arm64-v8a/libAQR.so':add(f.read(i.compress_size))
  else:
   assert (i.file_size,i.compress_size,i.CRC)==(old['size'],old['compressed_size'],old['crc']),i.filename
   commands.append(['copy',old['offset'],i.compress_size])
  cursor=start+i.compress_size
 f.seek(cursor);add(f.read())
 f.seek(0);assert hashlib.file_digest(f,'sha256').hexdigest()==target['apk_sha256']
assert sum(c[2] for c in commands)==target['apk_size']
manifest={'format':1,'source_sha256':source['source_sha256'],'source_size':source['source_size'],'target_sha256':target['apk_sha256'],'target_size':target['apk_size'],'literal_sha256':hashlib.sha256(literal).hexdigest(),'commands':commands}
with zipfile.ZipFile(a.output,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
 z.writestr('manifest.json',json.dumps(manifest,separators=(',',':')));z.writestr('literal.bin',literal)
print('Exact signed APK update:',a.output.stat().st_size,'bytes')
