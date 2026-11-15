"""Execute the original ARM64 activation decision and normalization in Unicorn."""
import json,struct,sys
from pathlib import Path
import lief
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
ROOT=Path(__file__).parent
BASE=0x100000000;HOST=0x200000000;STOP=HOST+0xf000;SP=HOST+0x1f0000
PATH=ROOT/'native/Payload/OXIDE.app/Frameworks/ultLoader.framework/ultLoader'
class Machine:
 def __init__(self,raw):
  self.raw=raw;self.b=lief.MachO.parse(list(raw)).at(0);self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20);self.heap=HOST+0x40000;self.objects={};self.names={};self.chosen=None
  self.u.mem_map(BASE,0xb00000);self.u.mem_map(HOST,0x200000)
  for s in self.b.segments:
   if s.file_size:self.u.mem_write(BASE+s.virtual_address,raw[s.file_offset:s.file_offset+s.file_size])
  for r in self.b.relocations:
   if hasattr(r,'target'):self.u.mem_write(BASE+r.address,struct.pack('<Q',BASE+r.target))
  for binding in self.b.dyld_chained_fixups.bindings:
   name=binding.symbol.name;p=next((a for a,n in self.names.items() if n==name),None)
   if p is None:p=HOST+len(self.names)*16;self.names[p]=name;self.u.mem_write(p,bytes.fromhex('c0035fd6'))
   self.u.mem_write(BASE+binding.address,struct.pack('<Q',p))
  self.u.hook_add(UC_HOOK_CODE,self.external,begin=HOST,end=HOST+0xefff)
  self.u.hook_add(UC_HOOK_CODE,self.selection,begin=BASE+0x1800,end=BASE+0x1800)
 def new(self,value):
  p=self.heap;self.heap+=32;self.objects[p]=value;return p
 def value(self,p):
  v=self.objects[p];return v['mutable'] if isinstance(v,dict) and 'mutable' in v else v
 def cstr(self,p):return bytes(self.u.mem_read(p,1024)).split(b'\0',1)[0].decode()
 def ret(self,v=0):self.u.reg_write(UC_ARM64_REG_X0,v);self.u.reg_write(UC_ARM64_REG_PC,self.u.reg_read(UC_ARM64_REG_LR))
 def selection(self,u,pc,size,data):
  self.chosen=self.cstr(u.reg_read(UC_ARM64_REG_X0));u.emu_stop()
 def external(self,u,pc,size,data):
  n=self.names[pc];a=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(5)]
  if n=='_objc_msgSend':
   selector=self.cstr(a[1]);obj=self.objects.get(a[0]);name=self.names.get(a[0]);v=self.value(a[0]) if a[0] in self.objects else None
   if selector=='stringWithUTF8String:':self.ret(self.new(self.cstr(a[2])))
   elif selector=='isEqualToString:':self.ret(int(v==self.value(a[2])))
   elif selector=='objectForKeyedSubscript:':self.ret(self.new(v[self.value(a[2])]))
   elif selector=='class':self.ret(a[0])
   elif selector=='isKindOfClass:':self.ret(int(isinstance(v,str) and self.names.get(a[2])=='_OBJC_CLASS_$_NSString'))
   elif selector=='whitespaceAndNewlineCharacterSet':self.ret(self.new('whitespace-set'))
   elif selector=='alphanumericCharacterSet':self.ret(self.new('alphanumeric-set'))
   elif selector=='stringByTrimmingCharactersInSet:':self.ret(self.new(v.strip()))
   elif selector=='uppercaseString':self.ret(self.new(v.upper()))
   elif selector=='length':self.ret(len(v))
   elif selector=='stringWithCapacity:':self.ret(self.new({'mutable':''}))
   elif selector=='characterAtIndex:':self.ret(ord(v[a[2]]))
   elif selector=='characterIsMember:':self.ret(int(chr(a[2]).isalnum()))
   elif selector=='appendFormat:':
    char=struct.unpack('<Q',bytes(u.mem_read(u.reg_read(UC_ARM64_REG_SP),8)))[0];self.objects[a[0]]['mutable']+=chr(char);self.ret()
   else:raise RuntimeError(('Unhandled Foundation selector',selector,name))
  elif n.startswith('_objc_retain') or n in ['_objc_autoreleaseReturnValue','_objc_autorelease','_objc_unsafeClaimAutoreleasedReturnValue']:self.ret(a[0])
  elif n=='_objc_release':self.ret()
  else:raise RuntimeError(('Unhandled import',n))
 def check(self,key):
  self.chosen=None;self.u.reg_write(UC_ARM64_REG_SP,SP);self.u.reg_write(UC_ARM64_REG_LR,STOP)
  self.u.reg_write(UC_ARM64_REG_X0,self.new('/v1/activate'));self.u.reg_write(UC_ARM64_REG_X1,self.new({'license_key':key}));self.u.reg_write(UC_ARM64_REG_X3,0)
  self.u.emu_start(BASE+0x2700,STOP,count=20000)
  assert self.chosen in ['response','error'],self.chosen
  return self.chosen=='response'
def verify(original,patched):
 before=Machine(original);after=Machine(patched);report={}
 cases=[('@Umbreladlc',True,False),('@Icon_Crack',False,True),('@icon_crack',False,True),('  @Icon_Crack\n',False,True),('ICONCRACK',False,True),('',False,False),('wrong-key',False,False),('@Icon_Crackx',False,False),('@Umbreladlcx',False,False)]
 for index,(key,old,new) in enumerate(cases):
  assert before.check(key)==old,('original case',index)
  assert after.check(key)==new,('patched case',index)
  report['case_'+str(index)+'_original_and_modified']=True
 report['actual_arm64_activation_and_normalizer_executed']=True
 return report
if __name__=='__main__':
 raw=PATH.read_bytes();patched=bytearray(raw);assert patched[0x2835:0x283f]==b'UMBRELADLC';patched[0x2835:0x283f]=b'ICONCRACK\0'
 report=verify(raw,bytes(patched));(ROOT/'activation-verification.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS: 9 original/patched activation scenarios using actual ARM64 normalization and key decision')
