"""Repackage unchanged IPA contents as ordinary ZIP32 records for IPA importers."""
import argparse,hashlib,json,shutil,struct,zipfile,zlib
from pathlib import Path

SOURCE_SHA256='a5d1691e1a64b4f5b78c9e518f18fa066e1f5cb8d960e3e1c2017aafd5daa54f'
p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('output',type=Path);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
assert a.source.resolve()!=a.output.resolve()
with a.source.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==SOURCE_SHA256
entries=[]
with zipfile.ZipFile(a.source) as source,zipfile.ZipFile(a.output,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6,allowZip64=False) as target:
    assert len(source.namelist())==len(set(source.namelist()))
    for old in source.infolist():
        new=zipfile.ZipInfo(old.filename,old.date_time)
        new.compress_type=zipfile.ZIP_DEFLATED;new._compresslevel=6
        new.create_system=old.create_system;new.external_attr=old.external_attr;new.internal_attr=old.internal_attr
        new.file_size=old.file_size;new.extra=b'';new.comment=old.comment
        with source.open(old) as src,target.open(new,'w',force_zip64=False) as dst:shutil.copyfileobj(src,dst,4*1024*1024)
    target.comment=source.comment
with zipfile.ZipFile(a.source) as source,zipfile.ZipFile(a.output) as target,a.output.open('rb') as raw:
    assert source.namelist()==target.namelist()
    for old,new in zip(source.infolist(),target.infolist()):
        assert (old.CRC,old.file_size,old.external_attr,old.internal_attr,old.create_system)==(new.CRC,new.file_size,new.external_attr,new.internal_attr,new.create_system)
        assert not new.flag_bits&8 and new.flag_bits&~0x800==0 and new.extract_version<=20 and not new.extra
        raw.seek(new.header_offset);h=raw.read(30)
        assert h[:4]==b'PK\x03\x04'
        assert struct.unpack_from('<III',h,14)==(new.CRC,new.compress_size,new.file_size)
        assert struct.unpack_from('<H',h,6)[0]==new.flag_bits
        with source.open(old) as src,target.open(new) as dst:
            original_digest=hashlib.file_digest(src,'sha256').hexdigest();new_digest=hashlib.file_digest(dst,'sha256').hexdigest()
        assert original_digest==new_digest,old.filename
        entries.append({'name':new.filename,'size':new.file_size,'sha256':new_digest})
    raw.seek(-22,2);end=raw.read(22);assert end[:4]==b'PK\x05\x06'
    assert struct.unpack_from('<HH',end,8)==(len(entries),len(entries))
with a.output.open('rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
report={'source_sha256':SOURCE_SHA256,'ipa_sha256':digest,'ipa_size':a.output.stat().st_size,'format':'ZIP32 / DEFLATE','data_descriptors':False,'local_crc_and_sizes_complete':True,'custom_deflate_padding':False,'all_file_bytes_unchanged':True,'all_entry_permissions_unchanged':True,'entry_count':len(entries),'zlib_version':zlib.ZLIB_RUNTIME_VERSION,'esign_device_tested':False,'entries':entries}
a.report.write_text(json.dumps(report,indent=2)+'\n')
a.output.with_name('SHA256SUMS-v2').write_text(digest+'  '+a.output.name+'\n')
print('PASS: standard ZIP32 IPA; all',len(entries),'entry contents and permissions preserved;',a.output.stat().st_size,'bytes;',digest,flush=True)
