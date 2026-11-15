import hashlib,json,os,plistlib,shutil,struct,subprocess,sys,zipfile
from pathlib import Path
from macho_util import add_dependency,sections,commands,dependencies
ROOT=Path(__file__).resolve().parent
WORK=Path('work').resolve();WORK.mkdir(exist_ok=True)
SOURCE=WORK/'build10-original.ipa'
SOURCE_SHA='933fa99531eba8db497c7ab2f12df38c1f04ab25612dfac175b457213d7c6f2a'
APP='Payload/OXIDE.app/'
NATIVE='Frameworks/ultLoader.framework/ultLoader'
DEPENDENCY='@executable_path/Frameworks/IconLink.framework/IconLink'
def run(args):subprocess.run([str(x) for x in args],check=True)
def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
assert SOURCE.stat().st_size==948871628 and sha(SOURCE)==SOURCE_SHA
blob=(ROOT/'alias.bin').read_bytes()
(WORK/'ICEmbeddedKey.h').write_text('static const unsigned char ICEmbeddedAlias[] = {'+','.join(str(v) for v in blob)+'};\n')
# Exercise the exact Foundation policy code on the macOS build host.
run(['clang','-fobjc-arc','-fblocks',ROOT/'ICPolicy.m',ROOT/'PolicyTests.m','-framework','Foundation','-o',WORK/'policy-tests'])
run([WORK/'policy-tests',ROOT/'alias.bin'])
framework=WORK/'new/IconLink.framework';framework.mkdir(parents=True,exist_ok=True)
info={'CFBundleExecutable':'IconLink','CFBundleIdentifier':'com.icon.crack.bridge.build10','CFBundleName':'IconLink','CFBundlePackageType':'FMWK','CFBundleShortVersionString':'2.0','CFBundleVersion':'2','MinimumOSVersion':'15.0','CFBundleSupportedPlatforms':['iPhoneOS']}
(framework/'Info.plist').write_bytes(plistlib.dumps(info,fmt=plistlib.FMT_BINARY));shutil.copyfile(ROOT/'alias.bin',framework/'alias.bin')
sdk=subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True).strip()
run(['xcrun','--sdk','iphoneos','clang','-arch','arm64','-isysroot',sdk,'-miphoneos-version-min=15.0','-I',WORK,'-fobjc-arc','-fblocks','-O2','-Wno-deprecated-declarations','-dynamiclib',ROOT/'IconLink.m',ROOT/'ICPolicy.m','-framework','Foundation','-framework','UIKit','-install_name','@rpath/IconLink.framework/IconLink','-o',framework/'IconLink'])
run([sys.executable,ROOT/'run_uikit_tests.py',WORK,sdk])
run(['codesign','--force','--sign','-','--timestamp=none',framework])
run(['codesign','--verify','--strict',framework])
new=framework/'IconLink';raw=new.read_bytes();assert struct.unpack_from('<I',raw,4)[0]==0x100000c
assert any(k==0x32 and struct.unpack_from('<I',c,8)[0]==2 for p,k,c in commands(raw)),'Companion is not an iOS binary'
with zipfile.ZipFile(SOURCE) as src:
 original_main=src.read(APP+'OXIDE');original_loader=src.read(APP+NATIVE)
 assert hashlib.sha256(original_loader).hexdigest()=='384255a15bf0375ef82d3e039cd4d986aa22296cc0cf8df638a57910b4e82ae2'
 main=WORK/'OXIDE';main.write_bytes(add_dependency(original_main,DEPENDENCY));main.chmod(0o755)
run(['codesign','--force','--sign','-','--timestamp=none','--identifier','com.catsbit.oxidesurvivalisland',main])
run(['codesign','--verify','--strict',main])
changed_main=main.read_bytes();assert DEPENDENCY in dependencies(changed_main)
for key,s in sections(original_main).items():
 if s['offset'] and s['size']:
  ns=sections(changed_main)[key]
  assert original_main[s['offset']:s['offset']+s['size']]==changed_main[ns['offset']:ns['offset']+ns['size']],('Main executable section changed',key)
replacements={APP+'OXIDE':changed_main}
for path in sorted(framework.rglob('*')):
 if path.is_file():replacements[APP+'Frameworks/IconLink.framework/'+str(path.relative_to(framework))]=path.read_bytes()
(WORK/'replacements.json').write_text(json.dumps({'paths':list(replacements)},indent=2)+'\n')
# Use ordinary ZIP32 local records with known sizes and CRCs, including unchanged payloads.
import zlib
out=WORK/'Ultima_iOS_Icon_Crack_v2.ipa';central=[];preserved=[];changed=[]
with zipfile.ZipFile(SOURCE) as src,SOURCE.open('rb') as inp,out.open('wb') as dst:
 assert len(src.namelist())==len(set(src.namelist()))
 entries=list(src.infolist())
 for name in replacements:
  if name not in src.namelist():
   i=zipfile.ZipInfo(name,(2026,11,15,0,0,0));i.compress_type=8;i.create_system=3;i.external_attr=((0o100755 if name.endswith('/IconLink') else 0o100644)<<16);entries.append(i)
 for i in entries:
  name=i.filename.encode();flags=0x800;method=i.compress_type;assert method in [0,8] and not i.flag_bits&1
  if i.filename in replacements:
   value=replacements[i.filename];size=len(value);crc=zlib.crc32(value);compress=zlib.compressobj(6,zlib.DEFLATED,-15);packed=compress.compress(value)+compress.flush();method=8;compressed=len(packed);changed.append({'name':i.filename,'size':size,'sha256':hashlib.sha256(value).hexdigest()})
  else:size=i.file_size;crc=i.CRC;compressed=i.compress_size;packed=None;preserved.append({'name':i.filename,'crc':crc,'size':size})
  y,m,d,h,mi,se=i.date_time;stamp=(h<<11)|(mi<<5)|(se//2);date=((y-1980)<<9)|(m<<5)|d;offset=dst.tell()
  dst.write(struct.pack('<4s5H3I2H',b'PK\3\4',20,flags,method,stamp,date,crc,compressed,size,len(name),0)+name)
  if packed is not None:dst.write(packed)
  else:
   inp.seek(i.header_offset);header=inp.read(30);n,x=struct.unpack_from('<HH',header,26);inp.seek(n+x,1);remaining=compressed
   while remaining:
    data=inp.read(min(remaining,4*1024*1024));assert data;dst.write(data);remaining-=len(data)
  central.append(struct.pack('<4s6H3I5H2I',b'PK\1\2',(i.create_system<<8)|max(20,i.create_version),20,flags,method,stamp,date,crc,compressed,size,len(name),0,0,0,i.internal_attr,i.external_attr,offset)+name)
 start=dst.tell();directory=b''.join(central);dst.write(directory);dst.write(struct.pack('<4s4H2IH',b'PK\5\6',0,0,len(central),len(central),len(directory),start,0))
assert out.stat().st_size<2*1024**3
with zipfile.ZipFile(out) as z,out.open('rb') as f:
 assert z.testzip() is None
 assert z.read(APP+NATIVE)==original_loader
 for i in z.infolist():
  assert not i.flag_bits&8 and i.extract_version<=20
  f.seek(i.header_offset);h=f.read(30);assert h[:4]==b'PK\3\4' and struct.unpack_from('<III',h,14)==(i.CRC,i.compress_size,i.file_size)
 for item in changed:assert hashlib.sha256(z.read(item['name'])).hexdigest()==item['sha256']
report={'source_sha256':SOURCE_SHA,'ipa_sha256':sha(out),'ipa_size':out.stat().st_size,'format':'ZIP32 / standard compression','data_descriptors':False,'all_crc_verified':True,'original_loader_bytes_unchanged':True,'original_game_payloads_preserved':len(preserved),'main_executable_original_sections_unchanged':True,'companion_platform':'iOS arm64 / iOS 15.0+','companion_and_main_adhoc_signatures_verified':True,'requires_installer_resigning':True,'embedded_key_resource_independent':True,'uikit_alias_tests_passed':True,'key':'@Icon_Crack','activation':'alias for supplied original server license; restrictions preserved','telegram':'https://t.me/Icon_Crack','phone_tested':False,'changed_entries':changed}
(WORK/'ultima-verification.json').write_text(json.dumps(report,indent=2)+'\n');(WORK/'SHA256SUMS.txt').write_text(report['ipa_sha256']+'  '+out.name+'\n')
print('PASS: IPA',out.stat().st_size,report['ipa_sha256'])
