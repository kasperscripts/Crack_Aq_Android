"""Small Mach-O checks: preserve all original sections, add one dependency."""
import struct,hashlib

def commands(raw):
    assert raw[:4]==bytes.fromhex('cffaedfe')
    p=32
    for _ in range(struct.unpack_from('<I',raw,16)[0]):
        kind,size=struct.unpack_from('<II',raw,p);assert size>=8 and size%8==0
        yield p,kind,raw[p:p+size];p+=size

def sections(raw):
    result={}
    for pos,kind,c in commands(raw):
        if kind!=0x19:continue
        count=struct.unpack_from('<I',c,64)[0]
        for i in range(count):
            at=72+80*i;name=c[at:at+16].split(b'\0')[0].decode();seg=c[at+16:at+32].split(b'\0')[0].decode();va,size,offset=struct.unpack_from('<QQI',c,at+32)
            flags=struct.unpack_from('<I',c,at+64)[0];result[(seg,name)]={'offset':offset,'size':size,'va':va,'flags':flags}
    return result

def dependencies(raw):
    return [c[struct.unpack_from('<I',c,8)[0]:].split(b'\0')[0].decode() for p,k,c in commands(raw) if k in [0xc,0x80000018,0x8000001f]]

def add_dependency(raw,name):
    data=bytearray(raw);assert name not in dependencies(raw)
    oldcount,oldsize=struct.unpack_from('<II',raw,16);p=32+oldsize;encoded=name.encode()+b'\0';size=(24+len(encoded)+7)&~7
    first=min(s['offset'] for s in sections(raw).values() if s['offset']>0 and s['size']>0)
    assert p+size<=first and not any(data[p:p+size]),'No load command padding'
    data[p:p+size]=struct.pack('<6I',0xc,size,24,0,0,0)+encoded+bytes(size-24-len(encoded))
    struct.pack_into('<II',data,16,oldcount+1,oldsize+size)
    for key,s in sections(raw).items():
        if s['offset'] and s['size']:assert raw[s['offset']:s['offset']+s['size']]==data[s['offset']:s['offset']+s['size']]
    return bytes(data)
