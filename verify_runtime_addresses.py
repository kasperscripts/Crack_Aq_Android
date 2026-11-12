#!/usr/bin/env python3
"""Check authenticated runtime RVAs against executable code in the bundled game."""
import argparse,json,struct,zipfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('apk',type=Path);p.add_argument('--config',type=Path,default=Path('runtime-config.json'));p.add_argument('--report',type=Path,required=True);a=p.parse_args();config=json.loads(a.config.read_text());checks=[]
with zipfile.ZipFile(a.apk) as z:
 with z.open('lib/arm64-v8a/libil2cpp.so') as f:head=f.read(65536)
 assert head[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',head,18)[0]==183
 phoff=struct.unpack_from('<Q',head,32)[0];entsize,num=struct.unpack_from('<HH',head,54);segments=[]
 for i in range(num):
  kind,flags,offset,va,_,size,_,_=struct.unpack_from('<IIQQQQQQ',head,phoff+i*entsize)
  if kind==1 and flags&1:segments.append((va,va+size,offset))
 with z.open('lib/arm64-v8a/libil2cpp.so') as f:
  for name,text in sorted(config['offsets'].items(),key=lambda item:int(item[1],16)):
   address=int(text,16);seg=next(s for s in segments if s[0]<=address<s[1]);assert address%4==0
   f.seek(address-seg[0]+seg[2]);code=f.read(16);assert len(code)==16 and code!=bytes(16)
   checks.append({'name':name,'rva':text,'executable_segment':True,'first_16_bytes':code.hex()})
a.report.write_text(json.dumps({'game_version':config['game_version'],'addresses':checks},indent=2)+'\n');print('PASS: all four runtime addresses are aligned executable code')
