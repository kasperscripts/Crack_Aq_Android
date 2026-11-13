"""Rebuild in-place ad-hoc Mach-O signatures; an installer must sign the IPA."""
import hashlib,struct

def command(raw):
    assert raw[:4]==bytes.fromhex('cffaedfe')
    off=32
    for _ in range(struct.unpack_from('<I',raw,16)[0]):
        cmd,size=struct.unpack_from('<II',raw,off)
        if cmd==0x1d:return struct.unpack_from('<II',raw,off+8)
        off+=size
    raise AssertionError('No LC_CODE_SIGNATURE')

def slots(raw):
    offset,capacity=command(raw);blob=raw[offset:offset+capacity]
    magic,length,count=struct.unpack_from('>III',blob)
    assert magic==0xfade0cc0 and length<=capacity
    result={}
    for i in range(count):
        kind,at=struct.unpack_from('>II',blob,12+i*8);n=struct.unpack_from('>I',blob,at+4)[0]
        result[kind]=blob[at:at+n]
    return result

def sign(raw,resources=None):
    raw=bytearray(raw);offset,capacity=command(raw);original=slots(raw)
    cd=bytearray(original.get(0x1000,original[0]))
    magic,length,version,flags,hash_offset,ident_offset,special,count,limit=struct.unpack_from('>9I',cd)
    hash_size,hash_type,_,page=struct.unpack_from('4B',cd,36)
    assert hash_size==32 and hash_type==2 and limit==offset and count==(limit+(1<<page)-1)>>page
    struct.pack_into('>I',cd,12,2) # CS_ADHOC
    if version>=0x20200:struct.pack_into('>I',cd,48,0) # No certificate team in an ad-hoc signature.
    requirements=struct.pack('>III',0xfade0c01,12,0)
    blobs={0:cd,2:requirements}
    for kind in [5,7]:
        if kind in original:blobs[kind]=original[kind]
    specials={2:requirements,5:blobs.get(5),7:blobs.get(7)}
    if resources is not None:specials[3]=resources
    for slot,data in specials.items():
        if slot<=special and data is not None:cd[hash_offset-slot*hash_size:hash_offset-(slot-1)*hash_size]=hashlib.sha256(data).digest()
    for i in range(count):
        digest=hashlib.sha256(raw[i*(1<<page):min((i+1)*(1<<page),limit)]).digest()
        cd[hash_offset+i*hash_size:hash_offset+(i+1)*hash_size]=digest
    body=bytearray();index=bytearray();start=12+8*len(blobs)
    for kind,data in blobs.items():
        index+=struct.pack('>II',kind,start+len(body));body+=data
    blob=struct.pack('>III',0xfade0cc0,start+len(body),len(blobs))+index+body
    assert len(blob)<=capacity
    raw[offset:offset+capacity]=blob+bytes(capacity-len(blob))
    return bytes(raw)

def verify(raw,resources=None):
    offset,capacity=command(raw);ss=slots(raw);assert 0x10000 not in ss
    cd=ss[0];_,_,version,flags,hash_offset,ident,special,count,limit=struct.unpack_from('>9I',cd)
    assert flags&2 and cd[37]==2 and cd[36]==32
    page=1<<cd[39]
    for i in range(count):assert cd[hash_offset+32*i:hash_offset+32*(i+1)]==hashlib.sha256(raw[i*page:min((i+1)*page,limit)]).digest()
    for slot,data in [(2,ss[2]),(5,ss.get(5)),(7,ss.get(7)),(3,resources)]:
        if data is not None and slot<=special:assert cd[hash_offset-slot*32:hash_offset-(slot-1)*32]==hashlib.sha256(data).digest()
    return {'code_pages_verified':count,'ad_hoc':True,'requires_installer_resigning':True,'cdhash_sha256':hashlib.sha256(cd).hexdigest()[:40]}
