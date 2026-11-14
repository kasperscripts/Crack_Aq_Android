import io,sys,struct,pathlib,time,re,os,hashlib,json
sys.path.insert(0,'/workspace/work/tools/pylibs')
from unicorn import *
from unicorn.arm64_const import *
from elftools.elf.elffile import ELFFile
R=pathlib.Path('/workspace/work/grandproject')
R=pathlib.Path('/workspace/work/phantom385');raw=pathlib.Path(os.environ.get('PHANTOM_AUTH',str(R/'native/liboxide_auth_bootstrap.so'))).read_bytes();elf=ELFFile(io.BytesIO(raw))
BASE=int(os.environ.get('ELF_BASE','0'),0)
u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
u.mem_map(0,0x2800000);u.mem_map(0x4000000,0x200000);u.mem_map(0x5000000,0x4000000)
for p in elf.iter_segments():
 if p['p_type']=='PT_LOAD':u.mem_write(BASE+p['p_vaddr'],p.data())
dyn=next(p for p in elf.iter_segments() if p['p_type']=='PT_DYNAMIC')
tags={t.entry.d_tag:t.entry.d_val for t in dyn.iter_tags()}
syms=list(dyn.iter_symbols());imports={};names={}
for s in syms:
 if s.name and s['st_shndx']=='SHN_UNDEF':
  a=0x4000000+len(imports)*16;imports[s.name]=a;names[a]=s.name;u.mem_write(a,bytes.fromhex('c0035fd6'))
for start,sz in [(tags['DT_RELA'],tags['DT_RELASZ']),(tags['DT_JMPREL'],tags['DT_PLTRELSZ'])]:
 for off in range(start,start+sz,24):
  a,info,v=struct.unpack('<QQq',bytes(u.mem_read(BASE+off,24)));ty=info&0xffffffff;ix=info>>32
  if ty==1027:v+=BASE
  elif ty in [257,1025,1026]:v+=imports.get(syms[ix].name,BASE+syms[ix]['st_value'])
  else:raise RuntimeError(('reloc',ty))
  u.mem_write(BASE+a,struct.pack('<Q',v))
STOP=0x401ff00;heap=0x5100000;files={};tls={}
u.reg_write(UC_ARM64_REG_SP,0x8fff000);u.reg_write(UC_ARM64_REG_TPIDR_EL0,0x4100000)
u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
def alloc(n):
 global heap
 a=heap;heap+=(n+15)&~15
 if heap>=0x8e00000:raise RuntimeError('heap full')
 return a
def s(a):return bytes(u.mem_read(a,4096)).split(b'\0')[0].decode(errors='replace') if a else ''
def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v&0xffffffffffffffff);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
def maps():
 return b''.join(f'{p["p_vaddr"]&~4095:08x}-{(p["p_vaddr"]+p["p_filesz"]+4095)&~4095:08x} {"rwxp"} {p["p_offset"]&~4095:08x} 00:00 1 /data/app/lib/arm64/libgrnd.so\n'.encode() for p in elf.iter_segments() if p['p_type']=='PT_LOAD')
outputs={};filepaths={};counter=100
import os
BOOT=pathlib.Path(os.environ.get('PHANTOM_BOOTSTRAP',str(R/'decoded/assets/bootstrap.bin'))).read_bytes()
def openfile(path,flags=0):
 global counter
 if path in outputs:b=outputs[path]
 elif path.endswith('/bootstrap.bin'):b=BOOT
 elif path.endswith('/license-runtime.json'):b=b'{"schema":2,"device_id":"'+b'0'*64+b'","mode":"root"}'
 elif flags&0x40:b=b''
 elif path=='/proc/self/maps':b=maps()
 else:print('FILE_MISSING',path,hex(flags),flush=True);return -2
 fd=counter;counter+=1;files[fd]=io.BytesIO(b);filepaths[fd]=path;print('OPEN',path,hex(flags),flush=True);return fd
def system(n,a):
 if n==56:return openfile(s(a[1]))
 if n==63:
  b=files[a[0]].read(a[2]);u.mem_write(a[1],b);return len(b)
 if n==67:
  files[a[0]].seek(a[3]);b=files[a[0]].read(a[2]);u.mem_write(a[1],b);return len(b)
 if n==62:return files[a[0]].seek(a[1],a[2])
 if n in [57,226,101]:return 0
 if n==222:return alloc(a[1])
 if n in [172,178]:return 1000
 raise RuntimeError(('syscall',n,[hex(v) for v in a]))
def intr(u,no,data):
 n=u.reg_read(UC_ARM64_REG_X8);a=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(6)]
 if no!=2:raise RuntimeError(('interrupt',no,hex(u.reg_read(UC_ARM64_REG_PC)),n))
 if n!=226:print('SYSCALL',n,[hex(v) for v in a[:3]],flush=True)
 v=system(n,a);u.reg_write(UC_ARM64_REG_X0,v&0xffffffffffffffff)
u.hook_add(UC_HOOK_INTR,intr)
def imp(u,addr,size,data):
 n=names[addr];a=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(8)]
 if n in ['memcpy','memmove','__memcpy_chk']:u.mem_write(a[0],bytes(u.mem_read(a[1],a[2])));ret(a[0])
 elif n in ['memset','__memset_chk']:u.mem_write(a[0],bytes([a[1]&255])*a[2]);ret(a[0])
 elif n in ['malloc','calloc']:ret(alloc(a[0]*(a[1] if n=='calloc' else 1)))
 elif n=='realloc':
  p=alloc(a[1]);u.mem_write(p,bytes(u.mem_read(a[0],a[1])) if a[0] else bytes(a[1]));ret(p)
 elif n in ['strlen']:ret(len(s(a[0]).encode()))
 elif n in ['strcmp','strncmp','memcmp']:
  x=bytes(u.mem_read(a[0],a[2])) if n=='memcmp' else s(a[0]).encode();y=bytes(u.mem_read(a[1],a[2])) if n=='memcmp' else s(a[1]).encode()
  if n=='strncmp':x=x[:a[2]];y=y[:a[2]]
  ret((x>y)-(x<y))
 elif n in ['__cxa_atexit','__cxa_finalize','__register_atfork','free','mprotect','pthread_mutex_init','pthread_mutex_lock','pthread_mutex_unlock','pthread_attr_init','pthread_attr_setdetachstate','pthread_attr_destroy','sigaction','sigemptyset','getauxval']:ret()
 elif n=='pthread_create':print('THREAD',hex(a[2]),hex(a[3]),flush=True);ret()
 elif n=='__errno':ret(0x4100100)
 elif n=='__system_property_get':
  v=b'36' if 'sdk' in s(a[0]) else b'';u.mem_write(a[1],v+b'\0');ret(len(v))
 elif n=='dladdr':
  p=alloc(64);u.mem_write(p,b'/runtime/liboxide_auth_bootstrap.so\0');u.mem_write(a[1],struct.pack('<4Q',p,BASE,0,0));ret(1)
 elif n=='getenv':ret(0)
 elif n=='clock_gettime':u.mem_write(a[1],struct.pack('<QQ',1000,0));ret(0)
 elif n=='localeconv':
  p=alloc(128);q=alloc(16);u.mem_write(q,b'.\0');u.mem_write(p,struct.pack('<10Q',q,*([q+1]*9)));ret(p)
 elif n in ['open','__open_2']:ret(openfile(s(a[0]),a[1]))
 elif n=='fstat':
  buf=bytearray(128);struct.pack_into('<I',buf,16,0o100500);struct.pack_into('<q',buf,48,len(files[a[0]].getvalue()));u.mem_write(a[1],bytes(buf));ret()
 elif n=='close':ret()
 elif n=='posix_memalign':
  v=alloc(a[2]+a[1]);v=(v+a[1]-1)&-a[1];u.mem_write(a[0],struct.pack('<Q',v));ret()
 elif n=='read':
  b=files[a[0]].read(a[2]);u.mem_write(a[1],b);ret(len(b))
 elif n=='mkstemp':
  path=s(a[0]).replace('XXXXXX','123456');u.mem_write(a[0],path.encode()+b'\0');ret(openfile(path,0x40))
 elif n=='write':
  b=bytes(u.mem_read(a[1],a[2]));files[a[0]].write(b);path=filepaths[a[0]];outputs[path]=files[a[0]].getvalue();print('WRITE',path,len(b),flush=True)
  if outputs[path].startswith(b'\x7fELF'):
   (R/'emulation/decrypted-runtime.so').write_bytes(outputs[path])
   raise CaptureDone()
  ret(len(b))
 elif n in ['fchmod','fsync','rename','unlink']:ret()
 elif n=='fopen':ret(0)
 elif n=='geteuid':ret(0)
 elif n=='android_dlopen_ext':print('PLAINTEXT_LIBRARY_READY',s(a[0]),flush=True);raise CaptureDone()
 elif n=='dlsym':ret(0)

 elif n=='syscall':ret(system(a[0],a[1:]))
 elif n in ['__android_log_print','__android_log_write']:print('LOG',s(a[1]),s(a[2]),flush=True);ret()
 else:raise RuntimeError(('import',n,[hex(v) for v in a[:4]],hex(u.reg_read(UC_ARM64_REG_LR))))
import_hook=u.hook_add(UC_HOOK_CODE,imp,begin=0x4000000,end=0x400ffff)
def invalid(u,access,addr,size,val,data):print('INVALID',access,hex(addr),size,'PC',hex(u.reg_read(UC_ARM64_REG_PC)),flush=True);return False
u.hook_add(UC_HOOK_MEM_INVALID,invalid)
def call(a,args=(),count=500000000):
 a+=BASE
 for i,v in enumerate(args):u.reg_write(UC_ARM64_REG_X0+i,v)
 u.reg_write(UC_ARM64_REG_SP,0x8fff000);u.reg_write(UC_ARM64_REG_LR,STOP)
 u.emu_start(a,STOP,count=count)
 if u.reg_read(UC_ARM64_REG_PC)!=STOP:raise RuntimeError(('incomplete',hex(u.reg_read(UC_ARM64_REG_PC))))
 return u.reg_read(UC_ARM64_REG_X0)


class CaptureDone(Exception): pass
if __name__=='__main__':
 print('AUTH_WORKER_START',flush=True)
 try:call(0x1f0c8,count=0)
 except CaptureDone:print('NATIVE_PACKAGE_VERIFICATION_AND_DECRYPTION_PASSED',flush=True)
 finally:
  for path,data in outputs.items():
   if len(data)>1024:(R/'emulation'/('capture-'+path.split('/')[-1])).write_bytes(data)
