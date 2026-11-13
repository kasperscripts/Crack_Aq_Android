from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
import re,json
root=Path(__file__).parent;p=root/'cf.bin';raw=p.read_bytes();f=p.open('rb');elf=ELFFile(f)
segs=[s for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
def offset(a):return next(a-s['p_vaddr']+s['p_offset'] for s in segs if s['p_vaddr']<=a<s['p_vaddr']+s['p_filesz'])
def string(a):
 try:
  off=offset(a);end=raw.find(b'\0',off);value=raw[off:end];return value.decode() if end>=0 and len(value)<4096 else ''
 except (StopIteration,UnicodeError):return ''
def wanted(s):return s=='RAVEN' or 'Raven iOS' in s or 'RAVENiOSPORTAL' in s
refs=[];regs={};cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM);cs.skipdata=True;sec=elf.get_section_by_name('.text')
for ins in cs.disasm(sec.data(),sec['sh_addr']):
 if ins.mnemonic=='adrp':r,a=ins.op_str.split(', ');regs[r]=(int(a[1:],16),ins.address)
 elif ins.mnemonic=='add':
  x=ins.op_str.split(', ')
  if len(x)==3 and x[1] in regs and x[2].startswith('#'):
   a,src=regs[x[1]];a+=int(x[2][1:],0);value=string(a)
   if wanted(value):refs.append({'kind':'adrp_add','adrp':src,'pc':ins.address,'target':a,'text':value,'operand':ins.op_str})
   regs[x[0]]=(a,src)
  else:regs.pop(x[0],None)
 elif ins.mnemonic in ['bl','blr']:
  for i in range(19):regs.pop('x'+str(i),None)
 elif ins.mnemonic.startswith('str') or ins.mnemonic in ['stp','cmp','tst','b','ret','nop'] or ins.mnemonic.startswith('b.'):pass
 else:regs.pop(ins.op_str.split(',')[0],None)
for sec in elf.iter_sections():
 if sec['sh_type']=='SHT_RELA':
  for index,r in enumerate(sec.iter_relocations()):
   a=r['r_addend'];s=string(a)
   if wanted(s):refs.append({'kind':'relocation','file_offset':sec['sh_offset']+index*sec['sh_entsize'],'relocation_address':r['r_offset'],'target':a,'text':s})
(root/'native-brand-refs.json').write_text(json.dumps(refs,indent=2))
for r in refs:print({k:hex(v) if isinstance(v,int) else v for k,v in r.items()})
