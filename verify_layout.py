#!/usr/bin/env python3
"""Check physical ZIP entry positions against the original APK layout."""
import argparse,hashlib,json,struct,zipfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('apk',type=Path);p.add_argument('--manifest',type=Path,default=Path('repack-verification.json'));p.add_argument('--report',type=Path,required=True);a=p.parse_args();manifest=json.loads(a.manifest.read_text());checked=0;different=[]
with zipfile.ZipFile(a.apk) as z,a.apk.open('rb') as f:
 names=set(z.namelist())
 for item in manifest['preserved_entries']:
  if item['name']=='stamp-cert-sha256' and item['name'] not in names:continue
  i=z.getinfo(item['name']);f.seek(i.header_offset);h=f.read(30);n,x=struct.unpack_from('<HH',h,26);offset=i.header_offset+30+n+x;f.seek(i.header_offset);header=f.read(30+n+x)
  if i.header_offset!=item['original_header_offset'] or offset!=item['original_data_offset'] or hashlib.sha256(header).hexdigest()!=item['original_local_header_sha256']:different.append({'name':i.filename,'header_offset_difference':i.header_offset-item['original_header_offset'],'data_offset_difference':offset-item['original_data_offset']})
  checked+=1
 report={'preserved_entry_layouts_checked':checked,'differences':different,'original_layout_preserved':not different,'native_entry_still_first':z.getinfo('lib/arm64-v8a/libAQR.so').header_offset==0}
a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'layouts_checked':checked,'different_layouts':len(different),'first_differences':different[:3]}));assert not different and report['native_entry_still_first']
