from pathlib import Path
import io,json,struct,hashlib
from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC
from unicorn.arm64_const import UC_ARM64_REG_X0
root=Path(__file__).parent;old=(root/'cf.bin').read_bytes();new=(root/'cf-icon.bin').read_bytes();a=ELFFile(io.BytesIO(old));b=ELFFile(io.BytesIO(new));report=json.loads((root/'native-patch-report.json').read_text());refs=json.loads((root/'native-brand-refs.json').read_text());targets={r['old_va']:r for r in report['literal_targets']};assert hashlib.sha256(old).hexdigest()==report['original_sha256'] and hashlib.sha256(new).hexdigest()==report['native_sha256'];old_loads=[s for s in a.iter_segments() if s['p_type']=='PT_LOAD'];new_loads=[s for s in b.iter_segments() if s['p_type']=='PT_LOAD'];assert [dict(s.header) for s in old_loads]==[dict(s.header) for s in new_loads[:-1]]
assert new_loads[-1]['p_flags']==4 and new_loads[-1]['p_align']==0x4000
allowed=set();note=next(i for i,s in enumerate(a.iter_segments()) if s['p_type']=='PT_NOTE');allowed.update(range(a['e_phoff']+note*a['e_phentsize'],a['e_phoff']+(note+1)*a['e_phentsize']))
def off(va):return next(va-s['p_vaddr']+s['p_offset'] for s in old_loads if s['p_vaddr']<=va<s['p_vaddr']+s['p_filesz'])
for r in refs:
 if r['kind']=='adrp_add':allowed.update(range(off(r['adrp']),off(r['adrp'])+8))
for sec in a.iter_sections():
 if sec['sh_type']=='SHT_RELA':
  for i,r in enumerate(sec.iter_relocations()):
   if r['r_addend'] in targets:
    expected=targets[r['r_addend']]['new_va'];assert b.get_section_by_name(sec.name).get_relocation(i)['r_addend']==expected;assert struct.unpack_from('<Q',new,off(r['r_offset']))[0]==expected
    allowed.update(range(sec['sh_offset']+24*i+16,sec['sh_offset']+24*i+24));allowed.update(range(off(r['r_offset']),off(r['r_offset'])+8))
assert all(i in allowed for i,(x,y) in enumerate(zip(old,new)) if x!=y)
for base in [0x100000000,0x7000000000]:
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(base,0x300000)
 for s in new_loads:u.mem_write(base+s['p_vaddr'],new[s['p_offset']:s['p_offset']+s['p_filesz']])
 u.mem_protect(base,0x300000,UC_PROT_READ|UC_PROT_WRITE);u.mem_protect(base,0x27c000,UC_PROT_READ|UC_PROT_EXEC);u.mem_protect(base+0x27c000,0x10000,UC_PROT_READ);u.mem_protect(base+new_loads[-1]['p_vaddr'],0x4000,UC_PROT_READ)
 for r in refs:
  if r['kind']!='adrp_add':continue
  u.emu_start(base+r['adrp'],base+r['adrp']+8,count=2);reg=int(r['operand'].split(',')[0][1:]);ptr=u.reg_read(UC_ARM64_REG_X0+reg);expected=targets[r['target']];assert ptr==base+expected['new_va'];text=expected['text'].encode()+b'\0';assert bytes(u.mem_read(ptr,len(text)))==text
report['aslr_instruction_execution_verified_bases']=['0x100000000','0x7000000000'];report['native_changes_limited_to_literal_references_relocations_and_read_only_segment']=True;report['localized_pointer_relocations_verified']=True;report['android_device_execution_tested']=False;(root/'native-verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print('PASS: native labels and URLs at two ASLR bases; original load segments and other code preserved')
