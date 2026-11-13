from pathlib import Path
import hashlib,json,struct,io
from elftools.elf.elffile import ELFFile
from keystone import Ks,KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN
ROOT=Path(__file__).parent;source=(ROOT/'cf.bin').read_bytes();assert hashlib.sha256(source).hexdigest()=='e8cc671fa8025500fe751b978d24333869307a26dd0691f13cca5ec43ad96042';raw=bytearray(source);elf=ELFFile(io.BytesIO(source));segs=[s for s in elf.iter_segments() if s['p_type']=='PT_LOAD'];refs=json.loads((ROOT/'native-brand-refs.json').read_text());ks=Ks(KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN)
def offset(a):return next(a-s['p_vaddr']+s['p_offset'] for s in segs if s['p_vaddr']<=a<s['p_vaddr']+s['p_filesz'])
file_start=(len(raw)+0x3fff)&~0x3fff;va_start=(max(s['p_vaddr']+s['p_memsz'] for s in segs)+0x3fff)&~0x3fff;payload=bytearray();strings={};mapped={};patches=[]
for r in refs:
 old=r['text'];new=old.replace('RAVENiOSPORTAL','Icon_Crack') if 'RAVENiOSPORTAL' in old else old.replace('Raven iOS','@Icon_Crack бай бай жирный') if 'Raven iOS' in old else '@Icon_Crack бай бай жирный'
 if new not in strings:strings[new]=va_start+len(payload);payload.extend(new.encode()+b'\0')
 mapped[r['target']]=strings[new]
for r in refs:
 if r['kind']!='adrp_add':continue
 assert r['pc']==r['adrp']+4
 dest,src,_=r['operand'].split(', ');value=mapped[r['target']];asm=f'adrp {src},#{value&~4095}; add {dest},{src},#{value&4095}';data=bytes(ks.asm(asm,r['adrp'])[0]);assert len(data)==8;at=offset(r['adrp']);raw[at:at+8]=data;patches.append({'kind':'ui_literal_reference','address':hex(r['adrp']),'size':8})
for sec in elf.iter_sections():
 if sec['sh_type']!='SHT_RELA':continue
 for index,r in enumerate(sec.iter_relocations()):
  if r['r_addend'] not in mapped:continue
  assert r['r_info_type']==1027;new=mapped[r['r_addend']];at=sec['sh_offset']+index*sec['sh_entsize']+16;struct.pack_into('<q',raw,at,new);struct.pack_into('<Q',raw,offset(r['r_offset']),new);patches.append({'kind':'localized_ui_string_pointer','address':hex(r['r_offset']),'new':hex(new)})
notes=[i for i,s in enumerate(elf.iter_segments()) if s['p_type']=='PT_NOTE'];assert len(notes)==1;at=elf['e_phoff']+notes[0]*elf['e_phentsize'];struct.pack_into('<IIQQQQQQ',raw,at,1,4,file_start,va_start,va_start,len(payload),len(payload),0x4000)
raw.extend(bytes(file_start-len(raw)));raw.extend(payload)
new_elf=ELFFile(io.BytesIO(raw));loads=[s for s in new_elf.iter_segments() if s['p_type']=='PT_LOAD'];assert len(loads)==len(segs)+1
for s in loads:assert s['p_offset']%0x4000==s['p_vaddr']%0x4000 and s['p_align']>=0x4000
for a,b in zip(loads,loads[1:]):assert a['p_vaddr']+a['p_memsz']<=b['p_vaddr']
symbol=next(s for s in elf.get_section_by_name('.dynsym').iter_symbols() if s.name=='JNI_OnLoad');at=offset(symbol['st_value']);assert source[at:at+symbol['st_size']]==raw[at:at+symbol['st_size']]
(ROOT/'cf-icon.bin').write_bytes(raw);digest=hashlib.sha256(raw).hexdigest();report={'original_sha256':hashlib.sha256(source).hexdigest(),'native_sha256':digest,'native_size':len(raw),'display':'@Icon_Crack бай бай жирный','telegram_target':'https://t.me/Icon_Crack','new_read_only_segment':{'file_offset':file_start,'virtual_address':va_start,'size':len(payload),'alignment':0x4000},'jni_onload_code_unchanged':True,'original_load_segments_unchanged':True,'patches':patches,'literal_targets':[{'old_va':old,'new_va':new,'text':next(k for k,v in strings.items() if v==new)} for old,new in mapped.items()]};(ROOT/'native-patch-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
import shutil
shutil.copytree(ROOT/'smali4',ROOT/'patched-smali4',dirs_exist_ok=True);p=ROOT/'patched-smali4/com/unity3d/player/CFLoader.smali';text=p.read_text();assert report['original_sha256'] in text;text=text.replace(report['original_sha256'],digest);p.write_text(text);print('Native branding references',len(patches),'new SHA',digest)
