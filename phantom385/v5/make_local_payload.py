from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os,base64,hashlib,zlib,struct
root=Path(__file__).parent;data=(root/'payload-local.so').read_bytes();key=os.urandom(32);iv=os.urandom(12)
assert data[:6]==b'\x7fELF\x02\x01'
phoff=struct.unpack_from('<Q',data,32)[0];phsize,phnum=struct.unpack_from('<HH',data,54)
image=hashlib.sha512()
for i in range(phnum):
    pos=phoff+i*phsize;kind,flags=struct.unpack_from('<II',data,pos)
    if kind==1 and not flags&2:
        offset=struct.unpack_from('<Q',data,pos+8)[0];size=struct.unpack_from('<Q',data,pos+32)[0]
        image.update(data[offset:offset+size])
b64=lambda b:base64.b64encode(b).decode()
s=b64(zlib.compress(data,9));chunks=[s[i:i+16000] for i in range(0,len(s),16000)]
code='''package dev.icon;
import android.util.Base64;
import java.io.*;
import java.util.zip.InflaterInputStream;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
public final class LocalPayload {
'''
for name,value in [('SHA256',hashlib.sha256(data).hexdigest()),('SHA512',hashlib.sha512(data).hexdigest()),('IMAGE_SHA512',image.hexdigest()),('KEY',b64(key)),('IV',b64(iv))]:code+='public static final String '+name+'="'+value+'";\n'
code+='public static final int SIZE='+str(len(data)+16)+';\nprivate static String[] chunks(){return new String[]{'+','.join('"'+x+'"' for x in chunks)+'};}\n'
code+='''public static byte[] bytes(){
try{
 StringBuilder s=new StringBuilder();for(String chunk:chunks())s.append(chunk);
 InflaterInputStream input=new InflaterInputStream(new ByteArrayInputStream(Base64.decode(s.toString(),Base64.NO_WRAP)));
 ByteArrayOutputStream output=new ByteArrayOutputStream(SIZE);
 byte[] buffer=new byte[16384];int n;
 try{while((n=input.read(buffer))!=-1){if(output.size()+n>SIZE-16)throw new IOException("local_payload_size");output.write(buffer,0,n);}}finally{input.close();}
 if(output.size()!=SIZE-16)throw new IOException("local_payload_size");
 Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
 cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(Base64.decode(KEY,Base64.NO_WRAP),"AES"),new GCMParameterSpec(128,Base64.decode(IV,Base64.NO_WRAP)));
 return cipher.doFinal(output.toByteArray());
}catch(Exception e){throw new IllegalStateException("local_payload_unavailable",e);}
}
}
'''
(root/'LocalPayload.java').write_text(code)
print('Payload raw',len(data),'compressed',len(zlib.compress(data,9)),'base64 chunks',len(chunks))
