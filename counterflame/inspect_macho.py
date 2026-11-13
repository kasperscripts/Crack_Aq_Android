import bisect,json,struct,sys
from pathlib import Path
import lief
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
root=Path(__file__).parent;p=root/'cf-menu.dylib';raw=p.read_bytes();b=lief.MachO.parse(str(p)).at(0);cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
segments=[s for s in b.segments if s.file_size]
def offset(v):return next(v-s.virtual_address+s.file_offset for s in segments if s.virtual_address<=v<s.virtual_address+s.file_size)
def read(v,n):o=offset(v);return raw[o:o+n]
def q(v):return struct.unpack('<Q',read(v,8))[0]
def cstr(v):return read(v,min(4096,len(raw)-offset(v))).split(b'\0')[0].decode(errors='replace')
functions=list(b.function_starts.functions);text=b.get_section('__text');functions.append(text.virtual_address+text.size);functions=sorted(set(functions))
symcmd=b.symbol_command;syms=list(b.symbols)
cmd=next(c for c in b.commands if c.command.name=='DYSYMTAB');indoff,num=struct.unpack_from('<II',bytes(cmd.data),56);indirect=struct.unpack_from('<'+str(num)+'I',raw,indoff);imports={}
for sec in b.sections:
 if sec.name=='__stubs':
  for i in range(sec.size//sec.reserved2):
   index=indirect[sec.reserved1+i]
   if index<len(syms):imports[sec.virtual_address+i*sec.reserved2]=syms[index].name
methods={}
def get_methods(cls,is_meta=False):
 ro=q(cls+32)&~7;name=cstr(q(ro+24));ml=q(ro+32)
 if not ml:return
 flags,count=struct.unpack('<II',read(ml,8));step=flags&0xffff
 for i in range(count):
  a=ml+8+i*step
  if flags&0x80000000:
   nr,tr,ir=struct.unpack('<iii',read(a,12));np=a+nr;np=np if flags&0x40000000 else q(np);label=cstr(np);imp=a+8+ir
  else:np,tp,imp=struct.unpack('<QQQ',read(a,24));label=cstr(np)
  methods[imp]=('+' if is_meta else '-')+'['+name+' '+label+']'
 if not is_meta:get_methods(q(cls),True)
sec=b.get_section('__objc_classlist')
for i in range(sec.size//8):
 try:get_methods(q(sec.virtual_address+i*8))
 except Exception as ex:print('class error',i,str(ex))
def dump(start,end):
 for ins in cs.disasm(read(start,end-start),start):
  note=''
  if ins.mnemonic in ['b','bl'] and ins.op_str.startswith('#0x'):
   target=int(ins.op_str[1:],16)
   if target in imports:note=' ; '+imports[target]
   elif target in methods:note=' ; '+methods[target]
  print(f'{ins.address:08x} {ins.mnemonic:9} {ins.op_str}{note}')
if __name__=='__main__':
 if len(sys.argv)>1:
  for x in sys.argv[1:]:
   a=int(x,0);i=bisect.bisect_right(functions,a)-1;s,e=functions[i:i+2];print('FUNCTION',hex(s),hex(e),methods.get(s,''));dump(s,e)
 else:
  for a,n in sorted(methods.items()):print(hex(a),n)
  (root/'objc-methods.json').write_text(json.dumps({hex(a):n for a,n in methods.items()},indent=2))
  (root/'stub-imports.json').write_text(json.dumps({hex(a):n for a,n in imports.items()},indent=2))
