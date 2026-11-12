import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
BASE=0x7000000000;HOST=BASE+0x10000000;STACK=HOST+0x3f0000;STOP=HOST+0xff000
class Image:
 def __init__(self,path=None):
  path=Path(path or Path(__file__).with_name('libAQR.so'));self.u=u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM64_MAX);u.mem_map(BASE,0x700000);u.mem_map(HOST,0x1000000);self.names={};self.alloc=HOST+0x500000;self.events=[]
  with path.open('rb') as f:
   e=ELFFile(f)
   for p in e.iter_segments():
    if p['p_type']=='PT_LOAD':u.mem_write(BASE+p['p_vaddr'],p.data())
   syms=list(e.get_section_by_name('.dynsym').iter_symbols());im={}
   for s in syms:
    if s['st_shndx']=='SHN_UNDEF' and s.name:
     a=HOST+16*len(im);im[s.name]=a;self.names[a]=s.name;u.mem_write(a,bytes.fromhex('c0035fd6'))
   for sn in ['.rela.dyn','.rela.plt']:
    for r in e.get_section_by_name(sn).iter_relocations():
     v=r['r_addend'];k=r['r_info_type']
     if k==1027:v+=BASE
     elif k in [257,1025,1026]:
      s=syms[r['r_info_sym']];v+=im.get(s.name,BASE+s['st_value'])
     else:raise ValueError(k)
     u.mem_write(BASE+r['r_offset'],struct.pack('<Q',v&((1<<64)-1)))
  u.reg_write(UC_ARM64_REG_TPIDR_EL0,HOST+0x400000);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20);u.hook_add(UC_HOOK_CODE,self.external,begin=HOST,end=HOST+0xffff)
 def reg(self,n):return self.u.reg_read(UC_ARM64_REG_X0+n)
 def ret(self,v=0):self.u.reg_write(UC_ARM64_REG_X0,v);self.u.reg_write(UC_ARM64_REG_PC,self.u.reg_read(UC_ARM64_REG_LR))
 def malloc(self,n):
  a=self.alloc;self.alloc+=(n+31)&~15;assert self.alloc<HOST+0xff0000;return a
 def cstr(self,a):return bytes(self.u.mem_read(a,8192)).split(b'\0')[0]
 def string(self,a):
  h=bytes(self.u.mem_read(a,24))
  if h[0]&1:n,p=struct.unpack('<QQ',h[8:]);return bytes(self.u.mem_read(p,n))
  return h[1:1+(h[0]>>1)]
 def putstr(self,a,s):
  if isinstance(s,str):s=s.encode()
  if len(s)<23:self.u.mem_write(a,bytes([len(s)*2])+s+bytes(23-len(s)))
  else:
   p=self.malloc(len(s)+1);self.u.mem_write(p,s+b'\0');self.u.mem_write(a,struct.pack('<QQQ',((len(s)+16)&~15)|1,len(s),p))
 def external(self,u,pc,size,data):
  n=self.names[pc];a=[self.reg(i) for i in range(5)]
  if n in ['__cxa_atexit','__cxa_finalize','__cxa_guard_release','__cxa_guard_abort','free','_ZdlPv','_ZdlPvm','__android_log_print'] or n.startswith('pthread_mutex_'):self.ret()
  elif n=='__cxa_guard_acquire':self.ret(1)
  elif n in ['malloc','_Znwm','_Znam']:self.ret(self.malloc(a[0]))
  elif n in ['memcpy','memmove','__memcpy_chk']:u.mem_write(a[0],bytes(u.mem_read(a[1],a[2])));self.ret(a[0])
  elif n in ['memset','__memset_chk']:u.mem_write(a[0],bytes([a[1]&255])*a[2]);self.ret(a[0])
  elif n=='syscall' and a[0]==178:self.ret(1234)
  elif n=='clock_gettime':u.mem_write(a[1],struct.pack('<QQ',1000,0));self.ret()
  elif n=='memchr':
   pos=bytes(u.mem_read(a[0],a[2])).find(bytes([a[1]&255]));self.ret(a[0]+pos if pos>=0 else 0)
  elif n=='__errno':self.ret(HOST+0x400100)
  elif n in ['strtoull','strtoul']:
   raw=self.cstr(a[0]);base=a[2];v=int(raw,base)
   if a[1]:u.mem_write(a[1],struct.pack('<Q',a[0]+len(raw)))
   self.ret(v)
  elif n=='strlen':self.ret(len(self.cstr(a[0])))
  elif n in ['memcmp','strcmp']:
   x,y=(bytes(u.mem_read(a[0],a[2])),bytes(u.mem_read(a[1],a[2]))) if n=='memcmp' else (self.cstr(a[0]),self.cstr(a[1]));self.ret((x>y)-(x<y))
  elif 'basic_string' in n:
   if n.endswith('D2Ev'):self.ret()
   elif n.endswith('aSERKS5_') or n.endswith('C1ERKS5_'):self.putstr(a[0],self.string(a[1]));self.ret(a[0])
   elif n.endswith('6assignEPKc'):self.putstr(a[0],self.cstr(a[1]));self.ret(a[0])
   else:raise RuntimeError(('unknown string',n))
  elif n=='_ZNSt6__ndk16chrono12steady_clock3nowEv':self.ret(1000000000000)
  else:raise RuntimeError(('import',n,[hex(x) for x in a]))
 def call(self,addr,*args,count=2000000):
  u=self.u;u.reg_write(UC_ARM64_REG_SP,STACK);u.reg_write(UC_ARM64_REG_LR,STOP)
  for i,a in enumerate(args):u.reg_write(UC_ARM64_REG_X0+i,a)
  try:u.emu_start(BASE+addr,STOP,count=count)
  except Exception as ex:raise RuntimeError(f'{hex(addr)} PC={hex(u.reg_read(UC_ARM64_REG_PC)-BASE)}: {ex}') from ex
  assert u.reg_read(UC_ARM64_REG_PC)==STOP,('instruction limit',hex(u.reg_read(UC_ARM64_REG_PC)-BASE));return self.reg(0)
 def init(self):
  for a in [0x1c4ee4,0x1c5030,0x22d1d8,0x287638,0x28d6cc,0x28d79c,0x28d86c,0x28d93c,0x314898,0x3612e4,0x3648ac]:self.call(a)
if __name__=='__main__':
 m=Image();m.init();Path(__file__).with_name('initialized-data.bin').write_bytes(bytes(m.u.mem_read(BASE+0x565430,0x68e70)));print('ctors OK')
