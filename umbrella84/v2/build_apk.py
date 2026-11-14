#!/usr/bin/env python3
"""Repack three entries; copy every other compressed stream unchanged."""
from pathlib import Path
import hashlib,io,json,struct,zipfile

ROOT=Path(__file__).resolve().parent

def patch_version(data):
    parts=[];pos=8;names=None
    while pos<len(data):
        kind,header,size=struct.unpack_from('<HHI',data,pos)
        assert size>=header>=8 and pos+size<=len(data)
        parts.append((kind,data[pos:pos+size]));pos+=size
    pool=next(c for k,c in parts if k==1)
    count,styles,flags,start,_=struct.unpack_from('<IIIII',pool,8);assert styles==0
    def length8(pos):
        n=pool[pos];return (((n&127)<<8)|pool[pos+1],pos+2) if n&128 else (n,pos+1)
    names=[]
    for i in range(count):
        pos=start+struct.unpack_from('<I',pool,28+4*i)[0]
        if flags&0x100:
            _,pos=length8(pos);n,pos=length8(pos);names.append(pool[pos:pos+n].decode())
        else:
            n=struct.unpack_from('<H',pool,pos)[0];assert not n&0x8000
            names.append(pool[pos+2:pos+2+n*2].decode('utf-16le'))
    output=[];changed=0
    for kind,c in parts:
        if kind==0x102 and names[struct.unpack_from('<I',c,20)[0]]=='manifest':
            c=bytearray(c);start,size,count=struct.unpack_from('<HHH',c,24);assert size==20
            for i in range(count):
                p=16+start+i*size
                if names[struct.unpack_from('<I',c,p+4)[0]]=='versionCode':
                    assert c[p+15]==0x10 and struct.unpack_from('<I',c,p+16)[0]==84
                    struct.pack_into('<I',c,p+16,86);changed+=1
        output.append(bytes(c))
    assert changed==1
    result=data[:8]+b''.join(output);assert len(result)==len(data)
    return result

def main():
    source=ROOT/'Umbrella-r84-beta12024-original.apk';output=ROOT/'Umbrella-unsigned.apk'
    blob=source.read_bytes();replacement={'classes7.dex':(ROOT/'classes7-icon.dex').read_bytes(),
        'lib/arm64-v8a/libumbrella.so':(ROOT/'libumbrella-icon.so').read_bytes()}
    with zipfile.ZipFile(source) as archive:
        replacement['AndroidManifest.xml']=patch_version(archive.read('AndroidManifest.xml'))
        size,magic=struct.unpack_from('<Q16s',blob,archive.start_dir-24)
        assert magic==b'APK Sig Block 42'
        signature_start=archive.start_dir-size-8
        endpos=blob.rfind(b'PK\x05\x06');assert endpos>archive.start_dir
        central=bytearray(blob[archive.start_dir:endpos]);end=bytearray(blob[endpos:])
        infos=sorted(archive.infolist(),key=lambda i:i.header_offset);records=bytearray();metadata={}
        for index,old in enumerate(infos):
            offset=len(records)
            if old.filename in replacement:
                info=zipfile.ZipInfo(old.filename,old.date_time);info.compress_type=old.compress_type
                info.external_attr=old.external_attr;info.create_system=old.create_system
                buffer=io.BytesIO()
                with zipfile.ZipFile(buffer,'w',allowZip64=False,compresslevel=9) as one:
                    one.writestr(info,replacement[old.filename]);local_end=one.start_dir
                record=buffer.getvalue()[:local_end]
                flags,method=struct.unpack_from('<HH',record,6)
                metadata[old.filename]={'offset':offset,'crc':info.CRC,'size':info.file_size,
                    'compressed_size':info.compress_size,'flags':flags,'method':method}
            else:
                limit=infos[index+1].header_offset if index+1<len(infos) else signature_start
                record=blob[old.header_offset:limit]
                metadata[old.filename]={'offset':offset}
            records.extend(record)
        cursor=0
        for old in archive.infolist():
            assert central[cursor:cursor+4]==b'PK\x01\x02'
            nn,xx,cc=struct.unpack_from('<HHH',central,cursor+28)
            name=bytes(central[cursor+46:cursor+46+nn]).decode()
            info=metadata[name];struct.pack_into('<I',central,cursor+42,info['offset'])
            if name in replacement:
                struct.pack_into('<HH',central,cursor+8,info['flags'],info['method'])
                struct.pack_into('<III',central,cursor+16,info['crc'],info['compressed_size'],info['size'])
            cursor+=46+nn+xx+cc
        assert cursor==len(central)
        struct.pack_into('<I',end,16,len(records))
        output.write_bytes(records+central+end)
        with zipfile.ZipFile(output) as rebuilt:
            assert rebuilt.namelist()==archive.namelist() and rebuilt.testzip() is None
            for old in archive.infolist():
                expected=replacement.get(old.filename)
                assert rebuilt.read(old.filename)==(expected if expected is not None else archive.read(old.filename)),old.filename
    (ROOT/'build-changes.json').write_text(json.dumps({'source_sha256':hashlib.sha256(blob).hexdigest(),
        'changed_entries':{name:hashlib.sha256(data).hexdigest() for name,data in replacement.items()},
        'other_compressed_streams_preserved':True,'version_code':86,
        'original_unsigned_library_records_removed':True},indent=2)+'\n')
    print('Repacked classes7.dex, library and package version; every other ZIP entry preserved')

if __name__=='__main__':main()
