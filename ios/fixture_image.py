from macho_image import *
from unicorn import UC_HOOK_MEM_WRITE,UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC

def initialized(patched=False,native_path=None,enforce_permissions=True):
    m=Image()
    if patched:
        old=d.raw[:0x3e8000];new=Path(native_path or d.root/'YouAreRetardBro-icon.dylib').read_bytes()[:0x3e8000]
        i=0
        while i<len(old):
            if old[i]==new[i]:i+=1;continue
            start=i
            while i<len(old) and old[i]!=new[i]:i+=1
            assert start<0x3e8000
            m.u.mem_write(BASE+start,new[start:i])
    m.call(0x18f4c8);view=m.obj(('instance','ImGuiDrawView'));m.call(0x2ec7c,view,0)
    block=next(b for b in m.dynamic.values() if int.from_bytes(m.u.mem_read(b+16,8),'little')==BASE+0x31268)
    if enforce_permissions:
        m.u.mem_protect(BASE,0x3e8000,UC_PROT_READ|UC_PROT_EXEC)
        m.u.mem_protect(BASE+0x3e8000,0x4000,UC_PROT_READ)
        m.u.mem_protect(BASE+0x3ec000,0xa8000,UC_PROT_READ|UC_PROT_WRITE)
        m.u.mem_protect(BASE+0x494000,0x1b000,UC_PROT_READ)
    m.runtime_permissions_enforced=enforce_permissions
    return m,view,block

def success(m,block):
    changed=set()
    def writes(u,access,address,size,value,data):
        changed.update(range(address-BASE,address-BASE+size))
    hook=m.u.hook_add(UC_HOOK_MEM_WRITE,writes,begin=BASE+0x46dc90,end=BASE+0x494000)
    invoke=int.from_bytes(m.u.mem_read(block+16,8),'little')-BASE
    assert invoke in [0x383e8,0x453b8]
    m.call(invoke,block)
    m.u.hook_del(hook)
    return changed

