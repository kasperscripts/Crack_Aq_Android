#!/usr/bin/env python3
"""Replace only libAQR.so, preserving all other APK compressed payloads."""
import argparse,hashlib,json,re,struct,zipfile,zlib
from pathlib import Path
SOURCE_SHA256='f3e7a0578efc652dc85c523df3bdb9e32011f19fdb2c806d5869b732b7815de4'
PAYLOAD='lib/arm64-v8a/libAQR.so'
SIGNATURE=re.compile(r'META-INF/(?:MANIFEST\.MF|[^/]+\.(?:SF|RSA|DSA|EC))',re.I)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('payload',type=Path);p.add_argument('output',type=Path);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    assert len({x.resolve() for x in [a.source,a.payload,a.output]})==3
    with a.source.open('rb') as f:source_hash=hashlib.file_digest(f,'sha256').hexdigest()
    assert source_hash in [SOURCE_SHA256,'c86417cbce75d6801fc167cf1d1c48339cfa2f265e913fb59877f856e80c28da','7123dc8c7a7ed4d1b39c283a1fecaee71e702868d07d3f6fcbde41725a01a6a5']
    central=[];changed=[];unchanged=[]
    with zipfile.ZipFile(a.source) as src,a.source.open('rb') as inp,a.output.open('wb') as out:
        replacements={PAYLOAD:a.payload.read_bytes()}
        for info in src.infolist():
            if SIGNATURE.fullmatch(info.filename):continue
            name=info.filename.encode('utf-8');method=info.compress_type;assert method in [0,8] and not info.flag_bits&1
            flags=(info.flag_bits&~8)|0x800
            size=info.file_size;compressed=info.compress_size;crc=info.CRC;replacement=None
            if info.filename in replacements:
                value=replacements[info.filename];size=len(value);crc=zlib.crc32(value)
                c=zlib.compressobj(6,zlib.DEFLATED,-15) if method==8 else None
                replacement=c.compress(value)+c.flush() if c else value;compressed=len(replacement)
                changed.append({'name':info.filename,'size':size,'sha256':hashlib.sha256(value).hexdigest()})
            else:unchanged.append({'name':info.filename,'crc32':f'{info.CRC:08x}','size':size,'compressed_size':compressed})
            hour,minute,second=info.date_time[3:];year,month,day=info.date_time[:3]
            stamp=(hour<<11)|(minute<<5)|(second//2);date=((year-1980)<<9)|(month<<5)|day
            offset=out.tell();alignment=16384 if method==0 and info.filename.endswith('.so') else 4
            padding=(-(offset+30+len(name)))%alignment
            if padding and padding<4:padding+=alignment
            extra=struct.pack('<HH',0xffff,padding-4)+bytes(padding-4) if padding else b''
            out.write(struct.pack('<4s5H3I2H',b'PK\x03\x04',20,flags,method,stamp,date,crc,compressed,size,len(name),len(extra))+name+extra)
            if replacement is not None:out.write(replacement)
            else:
                inp.seek(info.header_offset);header=inp.read(30);n,x=struct.unpack_from('<HH',header,26);inp.seek(n+x,1)
                remaining=compressed;digest=hashlib.sha256()
                while remaining:
                    block=inp.read(min(16*1024*1024,remaining));assert block;out.write(block);digest.update(block);remaining-=len(block)
                unchanged[-1]['compressed_sha256']=digest.hexdigest()
            central.append(struct.pack('<4s6H3I5H2I',b'PK\x01\x02',(info.create_system<<8)|info.create_version,20,flags,method,stamp,date,crc,compressed,size,len(name),0,0,0,info.internal_attr,info.external_attr,offset)+name)
        start=out.tell();body=b''.join(central);out.write(body);assert len(central)<65535
        out.write(struct.pack('<4s4H2IH',b'PK\x05\x06',0,0,len(central),len(central),len(body),start,0))
    a.report.write_text(json.dumps({'original_sha256':source_hash,'changed_entries':changed,'unchanged_compressed_streams':len(unchanged),'preserved_entries':unchanged,'unsigned_size':a.output.stat().st_size},indent=2)+'\n');print(a.output,flush=True)
if __name__=='__main__':main()
