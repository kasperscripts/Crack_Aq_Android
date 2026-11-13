from pathlib import Path
import argparse,hashlib,json,struct,zipfile,zlib
p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('apk',type=Path);p.add_argument('--report',type=Path,required=True);a=p.parse_args();root=Path(__file__).parent;r=json.loads((root/'apk-verification.json').read_text())
for path,digest in [(a.source,r['source_sha256']),(a.apk,r['apk_sha256'])]:
 with path.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==digest
assert a.apk.stat().st_size==r['apk_size']
with a.source.open('rb') as source,a.apk.open('rb') as apk:
 left=r['unchanged_original_local_body_prefix']
 while left:n=min(left,8*1024*1024);assert source.read(n)==apk.read(n);left-=n
entries=[];unchanged=0
with zipfile.ZipFile(a.source) as source,zipfile.ZipFile(a.apk) as apk:
 assert source.namelist()==apk.namelist()
 for info in apk.infolist():
  old=source.getinfo(info.filename)
  if info.filename in r['changed_entries']:
   with apk.open(info) as f:assert hashlib.file_digest(f,'sha256').hexdigest()==r['changed_entries'][info.filename]['sha256']
  else:assert (old.header_offset,old.file_size,old.compress_size,old.CRC,old.compress_type)==(info.header_offset,info.file_size,info.compress_size,info.CRC,info.compress_type);unchanged+=1
  with apk.open(info) as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
  entries.append({'name':info.filename,'size':info.file_size,'sha256':digest})
 for name,local in [('classes3.dex','classes3-icon.dex'),('classes4.dex','classes4-icon.dex'),('assets/binData/cf.bin','cf-icon.bin')]:assert apk.read(name)==(root/local).read_bytes()
 data=apk.read('classes4.dex');native_hash=hashlib.sha256(apk.read('assets/binData/cf.bin')).hexdigest();assert data.count(native_hash.encode())==1 and b'e8cc671fa8025500fe751b978d24333869307a26dd0691f13cca5ec43ad96042' not in data
r.update({'entry_count':len(entries),'unchanged_entries':unchanged,'all_unmodified_local_records_and_offsets_preserved':True,'all_zip_crc_and_file_sha256_verified':True,'bundled_native_sha256_guard_updated_and_preserved':True,'entries':entries});a.report.write_text(json.dumps(r,indent=2)+'\n');print('PASS: signed APK,',unchanged,'unchanged entries, new native hash guard, CRC and SHA-256 verified')
