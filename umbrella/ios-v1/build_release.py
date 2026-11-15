"""Patch the existing local key and presentation; preserve original game streams."""
import copy,hashlib,json,plistlib,struct,subprocess,zipfile,zlib
from pathlib import Path
from test_activation import verify
ROOT=Path(__file__).resolve().parent;WORK=Path('work').resolve();WORK.mkdir(exist_ok=True)
SOURCE=WORK/'original.ipa';EXPECTED='e31004fe122c13c49febb60b306630538119dd140fa4c1993b66b7ead08628fb'
APP='Payload/OXIDE.app/';LOADER=APP+'Frameworks/ultLoader.framework/ultLoader';OLD_RESOURCE=APP+'Umbreladlc.json';NEW_RESOURCE=APP+'Icon_Crack.json'
def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def sections(data):
 pos=32;out={}
 for _ in range(struct.unpack_from('<I',data,16)[0]):
  kind,size=struct.unpack_from('<II',data,pos)
  if kind==0x19:
   count=struct.unpack_from('<I',data,pos+64)[0]
   for n in range(count):
    at=pos+72+80*n;name=data[at:at+32];length,offset=struct.unpack_from('<QI',data,at+40);flags=struct.unpack_from('<I',data,at+64)[0]
    if offset and flags&255 not in [1,12,18]:out[name]=(offset,length)
  pos+=size
 return out
assert SOURCE.stat().st_size==948958000 and sha(SOURCE)==EXPECTED
with zipfile.ZipFile(SOURCE) as z:
 original=z.read(LOADER);assert hashlib.sha256(original).hexdigest()=='e88f7f9baf9a820c186be053f9b74d0b8b0d5b0542959bc4521fa0a3885f8a79'
 patched=bytearray(original)
 assert patched[0x18ec:0x18f6]==b'Umbreladlc' and patched[0x2835:0x283f]==b'UMBRELADLC'
 patched[0x18ec:0x18f6]=b'Icon_Crack'
 # The original normalizer removes @ and underscores, so compare ICONCRACK.
 patched[0x2835:0x283f]=b'ICONCRACK\0'
 checks=verify(original,bytes(patched));(WORK/'activation-verification.json').write_text(json.dumps(checks,indent=2)+'\n')
 native=WORK/'ultLoader';native.write_bytes(patched);native.chmod(0o755)
 subprocess.run(['codesign','--force','--sign','-','--timestamp=none',str(native)],check=True)
 subprocess.run(['codesign','--verify','--strict',str(native)],check=True)
 signed=native.read_bytes()
 assert signed[0x18ec:0x18f6]==b'Icon_Crack' and signed[0x2835:0x283f]==b'ICONCRACK\0'
 for name,(offset,length) in sections(original).items():
  newoffset,newlength=sections(signed)[name];assert length==newlength and original[offset:offset+length]==signed[newoffset:newoffset+newlength]
 oldinfo=z.read(APP+'Info.plist');newinfo=oldinfo.replace(b'@Umbreladlc',b'@Icon_Crack');assert plistlib.loads(newinfo)['CFBundleDisplayName']=='@Icon_Crack'
 resource=z.read(OLD_RESOURCE);oldjson=json.loads(resource)
 newjson=copy.deepcopy(oldjson);newjson['response']['message']='cracked by @Icon_Crack · https://t.me/Icon_Crack';newjson['error']['message']='Use @Icon_Crack · https://t.me/Icon_Crack'
 # All capability, session and runtime material stays exactly as supplied.
 for k in oldjson:
  if k not in ['response','error']:assert oldjson[k]==newjson[k]
 for k in ['response','error']:
  assert {n:v for n,v in oldjson[k].items() if n!='message'}=={n:v for n,v in newjson[k].items() if n!='message'}
 resource=json.dumps(newjson,ensure_ascii=False,separators=(',',':')).encode()
 replacements={LOADER:signed,APP+'Info.plist':newinfo,NEW_RESOURCE:resource}
 entries=[]
 for i in z.infolist():
  j=copy.copy(i)
  if j.filename==OLD_RESOURCE:j.filename=NEW_RESOURCE
  entries.append((i,j))
 assert len({j.filename for i,j in entries})==len(entries)
 out=WORK/'Umbrella_iOS_Icon_Crack.ipa';central=[];preserved=0;changed=[]
 with SOURCE.open('rb') as inp,out.open('wb') as dst:
  for old,i in entries:
   name=i.filename.encode();method=i.compress_type;assert method in [0,8] and not i.flag_bits&1
   if i.filename in replacements:
    value=replacements[i.filename];size=len(value);crc=zlib.crc32(value);compress=zlib.compressobj(6,zlib.DEFLATED,-15);packed=compress.compress(value)+compress.flush();method=8;compressed=len(packed);changed.append({'name':i.filename,'size':size,'sha256':hashlib.sha256(value).hexdigest()})
   else:size=i.file_size;crc=i.CRC;compressed=i.compress_size;packed=None;preserved+=1
   y,m,d,h,mi,se=i.date_time;stamp=(h<<11)|(mi<<5)|(se//2);date=((y-1980)<<9)|(m<<5)|d;offset=dst.tell()
   dst.write(struct.pack('<4s5H3I2H',b'PK\3\4',20,0x800,method,stamp,date,crc,compressed,size,len(name),0)+name)
   if packed is not None:dst.write(packed)
   else:
    inp.seek(old.header_offset);header=inp.read(30);n,x=struct.unpack_from('<HH',header,26);inp.seek(n+x,1);remaining=compressed
    while remaining:
     data=inp.read(min(remaining,4*1024*1024));assert data;dst.write(data);remaining-=len(data)
   central.append(struct.pack('<4s6H3I5H2I',b'PK\1\2',(i.create_system<<8)|max(20,i.create_version),20,0x800,method,stamp,date,crc,compressed,size,len(name),0,0,0,i.internal_attr,i.external_attr,offset)+name)
  start=dst.tell();directory=b''.join(central);dst.write(directory);dst.write(struct.pack('<4s4H2IH',b'PK\5\6',0,0,len(central),len(central),len(directory),start,0))
assert out.stat().st_size<2*1024**3
with zipfile.ZipFile(out) as z,out.open('rb') as f:
 assert z.testzip() is None and OLD_RESOURCE not in z.namelist() and NEW_RESOURCE in z.namelist()
 for i in z.infolist():
  assert i.extract_version<=20 and not i.flag_bits&8
  f.seek(i.header_offset);head=f.read(30);assert struct.unpack_from('<III',head,14)==(i.CRC,i.compress_size,i.file_size)
 for item in changed:assert hashlib.sha256(z.read(item['name'])).hexdigest()==item['sha256']
report={'source_sha256':EXPECTED,'ipa_sha256':sha(out),'ipa_size':out.stat().st_size,'all_crc_verified':True,'format':'ZIP32 / no data descriptors','original_loader_section_bytes_unchanged':True,'original_game_entries_preserved':preserved,'additional_runtime_modules':0,'key_check':'original ARM64 activation and normalization executed; 9 before/after scenarios passed','original_license_and_runtime_material_preserved':True,'local_key':'@Icon_Crack','telegram':'https://t.me/Icon_Crack','requires_esign_resigning':True,'physical_iphone_tested':False,'changed_entries':changed}
(WORK/'umbrella-verification.json').write_text(json.dumps(report,indent=2)+'\n');(WORK/'SHA256SUMS.txt').write_text(report['ipa_sha256']+'  '+out.name+'\n')
print('PASS: original ARM64 key checks, game streams, loader sections, codesign and IPA CRCs',flush=True)
print('IPA size:',report['ipa_size'],'SHA256:',report['ipa_sha256'])
