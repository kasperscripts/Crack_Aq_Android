#!/usr/bin/env python3
"""Relay an exact signed APK without uploading a signing key or unchanged assets."""
from pathlib import Path
import hashlib,json,struct,zipfile

ROOT=Path(__file__).resolve().parent

def main():
    source=ROOT/'Umbrella-r84-beta12024-original.apk'
    target=ROOT/'Umbrella_r84_Icon_Crack_nonroot.apk'
    patch=ROOT/'umbrella-r84-icon1.patch'
    old=source.read_bytes();new=target.read_bytes();literal=bytearray();commands=[];cursor=0
    def add(data):
        if data:commands.append(['data',len(literal),len(data)]);literal.extend(data)
    def stream(data,info):
        offset=info.header_offset;assert data[offset:offset+4]==b'PK\x03\x04'
        n,x=struct.unpack_from('<HH',data,offset+26)
        return offset+30+n+x
    with zipfile.ZipFile(source) as a,zipfile.ZipFile(target) as b:
        for info in sorted(b.infolist(),key=lambda i:i.header_offset):
            begin=stream(new,info);add(new[cursor:begin]);before=a.getinfo(info.filename)
            old_begin=stream(old,before)
            if (info.CRC,info.file_size,info.compress_size,info.compress_type)==(before.CRC,before.file_size,before.compress_size,before.compress_type):
                assert new[begin:begin+info.compress_size]==old[old_begin:old_begin+before.compress_size],info.filename
                commands.append(['copy',old_begin,info.compress_size])
            else:add(new[begin:begin+info.compress_size])
            cursor=begin+info.compress_size
        add(new[cursor:])
    assert sum(c[2] for c in commands)==len(new)
    manifest={'format':1,'source_sha256':hashlib.sha256(old).hexdigest(),'source_size':len(old),
        'target_sha256':hashlib.sha256(new).hexdigest(),'target_size':len(new),
        'literal_sha256':hashlib.sha256(literal).hexdigest(),'commands':commands}
    with zipfile.ZipFile(patch,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        z.writestr('manifest.json',json.dumps(manifest,separators=(',',':')))
        z.writestr('literal.bin',literal)
    print('Exact signed APK relay:',patch.stat().st_size,'bytes')

if __name__=='__main__':main()
