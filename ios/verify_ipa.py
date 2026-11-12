import hashlib,json,plistlib,struct,sys,zipfile
from pathlib import Path
from adhoc_sign import verify,sign,command
root=Path(__file__).parent;source=Path(sys.argv[1]);output=Path(sys.argv[2]);report=json.loads((root/'ipa-verification.json').read_text())
with source.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==report['source_sha256']
with output.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==report['ipa_sha256']
assert output.stat().st_size==report['ipa_size']
with zipfile.ZipFile(source) as a,zipfile.ZipFile(output) as b,source.open('rb') as old,output.open('rb') as new:
 assert a.namelist()==b.namelist() and b.testzip() is None
 for i in a.infolist():
  j=b.getinfo(i.filename);assert i.header_offset==j.header_offset and i.compress_size==j.compress_size
  if i.filename in report['changed_entries']:continue
  assert (i.CRC,i.file_size)==(j.CRC,j.file_size)
  old.seek(i.header_offset);header=old.read(30);n,x=struct.unpack_from('<HH',header,26);size=30+n+x+i.compress_size;old.seek(i.header_offset);new.seek(i.header_offset)
  while size:
   count=min(size,4*1024*1024);assert old.read(count)==new.read(count);size-=count
 native=b.read('Payload/OXIDE.app/YouAreRetardBro.dylib');assert native==sign((root/'YouAreRetardBro-icon.dylib').read_bytes());verify(native)
 resources=b.read('Payload/OXIDE.app/_CodeSignature/CodeResources');main=b.read('Payload/OXIDE.app/OXIDE');verify(main,resources);limit=command(main)[0];assert main[:limit]==a.read('Payload/OXIDE.app/OXIDE')[:limit]
 seals=plistlib.loads(resources);assert seals['files2']['YouAreRetardBro.dylib']['hash2']==hashlib.sha256(native).digest()
print('IPA SHA-256, all CRCs, 628 unchanged entries, offsets, game code and ad-hoc hashes verified')
