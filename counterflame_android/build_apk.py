from pathlib import Path
import argparse,hashlib,io,json,struct,subprocess,zipfile,zlib
p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('output',type=Path);p.add_argument('--keystore',type=Path,required=True);p.add_argument('--password-file',type=Path,required=True);p.add_argument('--alias',required=True);p.add_argument('--apksig',type=Path,required=True);a=p.parse_args();root=Path(__file__).parent
SOURCE='52ba20481e365b1da5b5b6f72402dde3d963fac474625392e77c81046e4d87f4'
with a.source.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==SOURCE
changes={'classes3.dex':root/'classes3-icon.dex','classes4.dex':root/'classes4-icon.dex','assets/binData/cf.bin':root/'cf-icon.bin'}
new_infos={};records=bytearray()
with zipfile.ZipFile(a.source) as z,a.source.open('rb') as f:
 central_offset=z.start_dir;f.seek(central_offset-24);length,magic=struct.unpack('<Q16s',f.read(24));assert magic==b'APK Sig Block 42';start=central_offset-length-8;f.seek(start);tail=f.read();eocd=tail.rfind(b'PK\x05\x06');assert eocd>=0 and len(tail)==eocd+22+struct.unpack_from('<H',tail,eocd+20)[0]
 old_size=a.source.stat().st_size;signature=tail[:central_offset-start];central=bytearray(tail[central_offset-start:eocd]);end=bytearray(tail[eocd:]);original_names=z.namelist()
 for name,path in changes.items():
  data=path.read_bytes();old=z.getinfo(name);info=zipfile.ZipInfo(name,old.date_time);info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=old.external_attr;info.create_system=old.create_system
  buffer=io.BytesIO()
  with zipfile.ZipFile(buffer,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9,allowZip64=False) as one:one.writestr(info,data);local_end=one.start_dir
  entry=buffer.getvalue()[:local_end];new_infos[name]={'offset':start+len(records),'crc':info.CRC,'compressed_size':info.compress_size,'size':len(data),'sha256':hashlib.sha256(data).hexdigest()};records.extend(entry)
 cursor=0
 for _ in z.infolist():
  assert central[cursor:cursor+4]==b'PK\x01\x02';nn,xx,cc=struct.unpack_from('<HHH',central,cursor+28);name=bytes(central[cursor+46:cursor+46+nn]).decode('utf-8',errors='replace')
  if name in new_infos:
   i=new_infos[name];struct.pack_into('<III',central,cursor+16,i['crc'],i['compressed_size'],i['size']);struct.pack_into('<I',central,cursor+42,i['offset'])
  cursor+=46+nn+xx+cc
 assert cursor==len(central);struct.pack_into('<I',end,16,start+len(records)+len(signature))
(root/'original-signature-tail.bin').write_bytes(tail)
try:
 with a.source.open('r+b') as f:f.seek(start);f.write(records);f.write(signature);f.write(central);f.write(end);f.truncate()
 with zipfile.ZipFile(a.source) as z:
  assert z.namelist()==original_names
  for name,info in new_infos.items():assert hashlib.sha256(z.read(name)).hexdigest()==info['sha256']
 subprocess.run(['java','-Xmx384m','--class-path',str(a.apksig),str(root/'PreserveLayoutSign.java'),str(a.source),str(a.output),str(a.keystore),str(a.password_file),a.alias],check=True)
finally:
 with a.source.open('r+b') as f:f.seek(start);f.write(tail);f.truncate(old_size)
with a.source.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==SOURCE
with a.output.open('rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
report={'source_sha256':SOURCE,'source_size':old_size,'apk_sha256':digest,'apk_size':a.output.stat().st_size,'unchanged_original_local_body_prefix':start,'changed_entries':new_infos,'old_original_records_preserved_as_unreferenced_history':True,'untouched_entries_keep_original_local_headers_offsets_and_streams':True,'provided_server_license_embedded':False,'physical_android_device_tested':False}
(root/'apk-verification.json').write_text(json.dumps(report,indent=2)+'\n');(root/'SHA256SUMS').write_text(digest+'  '+a.output.name+'\n');print('PASS: signed APK; original source restored; SHA256',digest,flush=True)
