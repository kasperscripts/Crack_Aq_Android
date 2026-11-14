import os,struct,sys,json
from pathlib import Path
root=Path(__file__).parent
os.environ['PHANTOM_AUTH']=sys.argv[1]
os.environ['PHANTOM_BOOTSTRAP']=str(root/'bootstrap-final.bin')
import emulate_auth as em
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import *

bundle=(root/'bootstrap-final.bin').read_bytes();n,size=struct.unpack('>II',bundle[8:16]);ui=bundle[16+n:16+n+size]
blob=em.alloc(len(ui));em.u.mem_write(blob,ui)
directory=em.alloc(24);em.u.mem_write(directory,b'\x10/runtime\0'+bytes(14))
vector=em.alloc(24);em.u.mem_write(vector,bytes(24))
class Rejected(Exception):pass
class Parsed(Exception):pass

def read_complete(u,pc,length,_):
    # Substitute only the already completed filesystem read. Parsing, AEAD,
    # length checks, vector allocation and PNG extraction execute natively.
    sp=u.reg_read(UC_ARM64_REG_SP)
    for off,value in [(0x2b0,len(ui)),(0x298,blob)]:u.mem_write(sp+off,struct.pack('<Q',value))
    table=em.alloc(64);u.mem_write(table,bytes(64))
    u.mem_write(sp+0x3a0,struct.pack('<Q',table+24))
    u.mem_write(sp+0x3c0,bytes(4))
    u.reg_write(UC_ARM64_REG_PC,0x4dfd8)
def thrown(u,pc,length,_):
    pointer=struct.unpack('<Q',bytes(u.mem_read(u.reg_read(UC_ARM64_REG_X0)+8,8)))[0]
    raise Rejected(em.s(pointer))
def done(u,pc,length,_):
    begin,end,capacity=struct.unpack('<QQQ',bytes(u.mem_read(vector,24)))
    assert bytes(u.mem_read(begin,end-begin))==(root/'ui-final.dex').read_bytes()
    assert any(v==(root/'menu_logo.png').read_bytes() for v in em.outputs.values())
    raise Parsed()
em.u.hook_add(UC_HOOK_CODE,read_complete,begin=0x4dd88,end=0x4dd88)
em.u.hook_add(UC_HOOK_CODE,thrown,begin=0x8de68,end=0x8de68)
em.u.hook_add(UC_HOOK_CODE,done,begin=0x4ee28,end=0x4ee28)
try:
    em.call(0x4db38,(directory,vector),count=0)
except Rejected as e:
    print('UI parser rejected:',str(e),flush=True)
    assert os.environ.get('EXPECT_REJECTION'),str(e)
except Parsed:
    assert not os.environ.get('EXPECT_REJECTION')
    print('Native UI parser accepted DEX and extracted unchanged PNG',flush=True)
