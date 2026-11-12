#!/usr/bin/env python3
"""Replace one same-size library while preserving the source APK entry layout."""
import argparse,hashlib,json,shutil,struct,zipfile,zlib
from pathlib import Path
SOURCE='f3e7a0578efc652dc85c523df3bdb9e32011f19fdb2c806d5869b732b7815de4'
PAYLOAD='lib/arm64-v8a/libAQR.so'
p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('native',type=Path);p.add_argument('output',type=Path);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
assert len({x.resolve() for x in [a.source,a.native,a.output]})==3
with a.source.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==SOURCE
raw=a.native.read_bytes();crc=zlib.crc32(raw);preserved=[]
with zipfile.ZipFile(a.source) as z,a.source.open('rb') as f:
 i=z.getinfo(PAYLOAD);assert i.compress_type==8 and i.file_size==len(raw) and not i.flag_bits&8
 f.seek(i.header_offset);header=f.read(30);n,x=struct.unpack_from('<HH',header,26);start=i.header_offset+30+n+x
 for level,mem in [(9,8),(9,7),(8,8),(9,6)]:
  c=zlib.compressobj(level,zlib.DEFLATED,-15,mem);stream=c.compress(raw)+c.flush(zlib.Z_SYNC_FLUSH);gap=i.compress_size-len(stream)
  candidates=[k for k in range(1,5) if gap>=(10*k+7)//8 and (gap-(10*k+7)//8)%5==0]
  if candidates:
   k=candidates[0];end_bytes=(10*k+7)//8;blocks=(gap-end_bytes)//5
   bits=sum((3 if j==k-1 else 2)<<(10*j) for j in range(k))
   packed=stream+b'\x00\x00\x00\xff\xff'*blocks+bits.to_bytes(end_bytes,'little');break
 else:raise AssertionError('patched library does not fit the original compressed entry')
 assert len(packed)==i.compress_size
 d=zlib.decompressobj(-15);assert d.decompress(packed)+d.flush()==raw and d.eof and not d.unused_data and not d.unconsumed_tail
 f.seek(z.start_dir);cursor=z.start_dir;central_crc=None
 for _ in z.infolist():
  h=f.read(46);assert h[:4]==b'PK\x01\x02';nn,xx,cc=struct.unpack_from('<HHH',h,28);name=f.read(nn).decode('utf-8');f.seek(xx+cc,1)
  if name==PAYLOAD:central_crc=cursor+16
  cursor+=46+nn+xx+cc
 assert central_crc is not None
 for info in z.infolist():
  f.seek(info.header_offset);h=f.read(30);nn,xx=struct.unpack_from('<HH',h,26);offset=info.header_offset+30+nn+xx
  if info.filename==PAYLOAD:continue
  f.seek(info.header_offset);record=f.read(30+nn+xx);digest=hashlib.sha256();remaining=info.compress_size
  while remaining:
   block=f.read(min(16*1024*1024,remaining));assert block;digest.update(block);remaining-=len(block)
  preserved.append({'name':info.filename,'crc32':f'{info.CRC:08x}','size':info.file_size,'compressed_size':info.compress_size,'compressed_sha256':digest.hexdigest(),'original_header_offset':info.header_offset,'original_data_offset':offset,'original_local_header_sha256':hashlib.sha256(record).hexdigest()})
shutil.copyfile(a.source,a.output)
with a.output.open('r+b') as f:
 f.seek(start);f.write(packed)
 for address in [i.header_offset+14,central_crc]:f.seek(address);f.write(struct.pack('<I',crc))
report={'original_sha256':SOURCE,'changed_entries':[{'name':PAYLOAD,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}],'unchanged_compressed_streams':len(preserved),'preserved_entries':preserved,'unsigned_size':a.output.stat().st_size,'original_entry_order_headers_offsets_and_compression_preserved':True,'native_compressed_size_preserved':i.compress_size,'native_deflate_padding_is_valid_empty_blocks':True,'modified_ranges':[[i.header_offset+14,4],[start,len(packed)],[central_crc,4]]}
a.report.write_text(json.dumps(report,indent=2)+'\n');print('In-place layout preserved:',len(preserved),'entries; native',len(packed),'compressed bytes',flush=True)
