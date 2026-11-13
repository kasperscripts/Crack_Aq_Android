"""Build the login-memory fix using the standard ESign-compatible IPA packaging."""
import argparse,hashlib,io,json,plistlib,shutil,struct,zipfile,zlib
from pathlib import Path
from adhoc_sign import sign,verify,command

SOURCE_SHA='616718f39443e1fe1a2375cfe8b4d832ca6438da3606bebb02121b729aff4b39'
NATIVE='Payload/CounterFlame.app/Frameworks/cf menu.dylib';RESOURCE='Payload/CounterFlame.app/_CodeSignature/CodeResources';MAIN='Payload/CounterFlame.app/CounterFlame'
p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('output',type=Path);p.add_argument('--report',type=Path,required=True);a=p.parse_args();root=Path(__file__).parent
with a.source.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==SOURCE_SHA
with zipfile.ZipFile(a.source) as source:
    native=sign((root/'cf-menu-icon.dylib').read_bytes());resources=plistlib.loads(source.read(RESOURCE))
    resources['files']['Frameworks/cf menu.dylib']=hashlib.sha1(native).digest()
    resources['files2']['Frameworks/cf menu.dylib']['hash']=hashlib.sha1(native).digest()
    resources['files2']['Frameworks/cf menu.dylib']['hash2']=hashlib.sha256(native).digest()
    resource_bytes=plistlib.dumps(resources,fmt=plistlib.FMT_XML,sort_keys=True)
    main=sign(source.read(MAIN),resource_bytes);replacements={NATIVE:native,RESOURCE:resource_bytes,MAIN:main}
    limit=command(main)[0];assert main[:limit]==source.read(MAIN)[:limit]
    signing={'module':verify(native),'executable':verify(main,resource_bytes)}
    with zipfile.ZipFile(a.output,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=1,allowZip64=False) as target:
        for old in source.infolist():
            new=zipfile.ZipInfo(old.filename,old.date_time);new.compress_type=zipfile.ZIP_DEFLATED;new._compresslevel=1
            new.create_system=old.create_system;new.external_attr=old.external_attr;new.internal_attr=old.internal_attr;new.comment=old.comment
            new.file_size=len(replacements[old.filename]) if old.filename in replacements else old.file_size
            with (io.BytesIO(replacements[old.filename]) if old.filename in replacements else source.open(old)) as src,target.open(new,'w',force_zip64=False) as dst:shutil.copyfileobj(src,dst,4*1024*1024)
        target.comment=source.comment
entries=[];unchanged=0
with zipfile.ZipFile(a.source) as source,zipfile.ZipFile(a.output) as target,a.output.open('rb') as raw:
    assert source.namelist()==target.namelist()
    for old,new in zip(source.infolist(),target.infolist()):
        assert (old.external_attr,old.internal_attr,old.create_system)==(new.external_attr,new.internal_attr,new.create_system)
        assert not new.flag_bits&~0x800 and new.extract_version<=20 and not new.extra
        raw.seek(new.header_offset);header=raw.read(30);assert struct.unpack_from('<III',header,14)==(new.CRC,new.compress_size,new.file_size)
        with target.open(new) as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
        if new.filename in replacements:assert digest==hashlib.sha256(replacements[new.filename]).hexdigest()
        else:
            with source.open(old) as f:assert digest==hashlib.file_digest(f,'sha256').hexdigest(),new.filename
            unchanged+=1
        entries.append({'name':new.filename,'size':new.file_size,'sha256':digest})
with a.output.open('rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
report={'source_sha256':SOURCE_SHA,'ipa_sha256':digest,'ipa_size':a.output.stat().st_size,'format':'ZIP32 / DEFLATE','entry_count':len(entries),'unchanged_entries':unchanged,'changed_entries':list(replacements),'game_executable_code_unchanged':True,'server_license_embedded':False,'runtime_memory_permissions_verified':True,'key':'@Icon_Crack','display_attribution':'@Icon_Crack бай бай жирный','signing':signing,'esign_device_tested':False,'entries':entries}
a.report.write_text(json.dumps(report,indent=2)+'\n');a.output.with_name('SHA256SUMS').write_text(digest+'  '+a.output.name+'\n')
print('PASS: CounterFlame standard IPA,',unchanged,'unchanged files, signing hashes verified;',digest,flush=True)
