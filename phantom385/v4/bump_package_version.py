from pathlib import Path
import sys,struct,json,zipfile
sys.path.insert(0,'/workspace/work/delta/repository')
from android16_compat import chunks,strings
root=Path(__file__).parent
source=Path('/workspace/work/aq/repository/artifacts/Phantom_3.5.85_Icon_Crack_v3.apk')
with zipfile.ZipFile(source) as archive:original=archive.read('AndroidManifest.xml')
parts=list(chunks(original));pool=next(v for kind,v in parts if kind==1);names,raw,flags=strings(pool);output=[];modified=[]
for kind,chunk in parts:
    if kind==0x102 and names[struct.unpack_from('<I',chunk,20)[0]]=='manifest':
        chunk=bytearray(chunk);start,size,count=struct.unpack_from('<HHH',chunk,24);assert size==20
        for i in range(count):
            pos=16+start+i*size;name=names[struct.unpack_from('<I',chunk,pos+4)[0]]
            if name=='versionCode':
                assert chunk[pos+15]==0x10;before=struct.unpack_from('<I',chunk,pos+16)[0];assert before==105;struct.pack_into('<I',chunk,pos+16,106);modified.append({'attribute':name,'before':before,'after':106})
            elif name=='versionName':
                assert chunk[pos+15]==3;index=struct.unpack_from('<I',chunk,pos+16)[0];assert names[index]=='3.5.85-hardened';new='3.5.85-icon4'
                raw[index]=bytes([len(new),len(new)])+new.encode()+b'\0' if flags&0x100 else struct.pack('<H',len(new))+new.encode('utf-16le')+b'\0\0'
                modified.append({'attribute':name,'before':names[index],'after':new})
        chunk=bytes(chunk)
    output.append((kind,chunk))
assert len(modified)==2
offsets=[];payload=b''
for value in raw:offsets.append(len(payload));payload+=value
payload+=bytes(-len(payload)%4);begin=28+4*len(raw)
new_pool=struct.pack('<HHIIIIII',1,28,begin+len(payload),len(raw),0,flags&~1,begin,0)+struct.pack('<'+'I'*len(offsets),*offsets)+payload
body=b''.join(new_pool if kind==1 else chunk for kind,chunk in output);result=struct.pack('<HHI',3,8,8+len(body))+body
list(chunks(result));(root/'manifest-v4.bin').write_bytes(result)
(root/'package-version-verification.json').write_text(json.dumps({'changes':modified,'package_name_preserved':True,'permissions_and_components_preserved':True,'payload_protocol_release':105},indent=2)+'\n')
print('Android package version increased to 106 / 3.5.85-icon4; native release remains 105')
