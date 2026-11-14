import os,sys,struct,json,hashlib,io,time
from pathlib import Path
root=Path(__file__).parent
os.environ['PHANTOM_AUTH']=sys.argv[1]
os.environ['PHANTOM_BOOTSTRAP']=str(root/'bootstrap-original.bin')
import emulate_auth as em
from unicorn import *
from unicorn.arm64_const import *

inventory=json.loads(Path(sys.argv[2]).read_text())
methods={m['name']:m['address'] for m in inventory['methods']}
JNI=0x4120000;TABLE=0x4121000
em.u.mem_write(JNI,struct.pack('<Q',TABLE))
arrays={};strings={};counter=0x4130000
def jstring(s):
    global counter
    p=counter;counter+=0x1000;strings[p]=s
    em.u.mem_write(p,s.encode()+b'\0');return p
def jarray(b):
    global counter
    p=counter;counter+=0x1000;arrays[p]=bytearray(b)
    q=em.alloc(len(b)+1);em.u.mem_write(q,bytes(b)+b'\0');arrays[p]=(bytearray(b),q);return p
def jni(u,pc,size,_):
    idx=(pc-0x4020000)//16;a=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(8)]
    if idx in [169,165]:em.ret(a[1])
    elif idx in [170,166,192]:em.ret()
    elif idx==167:em.ret(jstring(em.s(a[1])))
    elif idx==171:em.ret(len(arrays[a[1]][0]))
    elif idx==176:em.ret(jarray(bytes(a[1])))
    elif idx==184:em.ret(arrays[a[1]][1])
    elif idx==200:em.u.mem_write(a[4],bytes(arrays[a[1]][0][a[2]:a[2]+a[3]]));em.ret()
    elif idx==208:
        b=bytes(u.mem_read(a[4],a[3]));arrays[a[1]][0][a[2]:a[2]+a[3]]=b;u.mem_write(arrays[a[1]][1]+a[2],b);em.ret()
    elif idx in [228,15,17]:em.ret()
    else:raise RuntimeError(('JNI',idx,[hex(x) for x in a[:5]],hex(u.reg_read(UC_ARM64_REG_LR))))
for i in range(234):
    addr=0x4020000+i*16
    em.u.mem_write(addr,bytes.fromhex('c0035fd6'));em.u.mem_write(TABLE+i*8,struct.pack('<Q',addr))
jni_hook=em.u.hook_add(UC_HOOK_CODE,jni,begin=0x4020000,end=0x4021000)
em.u.hook_del(em.import_hook)
oldimp=em.imp;now=int(time.time());monotonic=1000;file_seals={};scheduled_threads=[]
def imports(u,pc,size,_):
    n=em.names[pc];a=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(8)]
    if n=='clock_gettime':u.mem_write(a[1],struct.pack('<QQ',monotonic if a[0] else now,0));em.ret()
    elif n in ['getpid','gettid']:em.ret(1000)
    elif n in ['pthread_setspecific','pthread_once','pthread_rwlock_wrlock','pthread_rwlock_rdlock','pthread_rwlock_unlock']:em.ret()
    elif n=='pthread_key_create':u.mem_write(a[0],struct.pack('<I',1));em.ret()
    elif n=='pthread_create':
        u.mem_write(a[0],struct.pack('<Q',1234));scheduled_threads.append({'function':a[2],'argument':a[3]});em.ret()
    elif n in ['pthread_detach','pthread_mutex_destroy','pthread_cond_broadcast','pthread_key_delete']:em.ret()
    elif n=='pthread_getspecific':em.ret(0)
    elif n=='opendir':
        # The isolated process has no Android task directory. Native checks
        # still execute and receive the OS failure rather than a fake result.
        assert em.s(a[0])=='/proc/self/task';em.ret(0)
    elif n=='getrandom':u.mem_write(a[0],bytes(range(a[1])));em.ret(a[1])
    elif n=='open' and em.s(a[0])=='/dev/urandom':em.files[99]=io.BytesIO(bytes(range(256))*10);em.ret(99)
    elif n=='syscall' and a[0]==278:u.mem_write(a[1],bytes(range(a[2])));em.ret(a[2])
    elif n=='fcntl':
        if a[1]==0x409:file_seals[a[0]]=file_seals.get(a[0],0)|a[2];em.ret()
        elif a[1]==0x40a:em.ret(file_seals.get(a[0],0))
        else:raise RuntimeError(('fcntl',a[:3]))
    elif n=='pread':
        stream=em.files[a[0]];position=stream.tell();stream.seek(a[3]);data=stream.read(a[2]);stream.seek(position);u.mem_write(a[1],data);em.ret(len(data))
    else:oldimp(u,pc,size,_)
em.u.hook_add(UC_HOOK_CODE,imports,begin=0x4000000,end=0x400ffff)
if os.environ.get('STRICT_MEMORY'):
    em.u.mem_protect(0,0x2800000,UC_PROT_READ)
    for segment in em.elf.iter_segments():
        if segment['p_type']!='PT_LOAD':continue
        start=(em.BASE+segment['p_vaddr'])&~4095;end=(em.BASE+segment['p_vaddr']+segment['p_memsz']+4095)&~4095
        flags=segment['p_flags'];permission=(UC_PROT_READ if flags&4 else 0)|(UC_PROT_WRITE if flags&2 else 0)|(UC_PROT_EXEC if flags&1 else 0)
        em.u.mem_protect(start,end-start,permission)
    for segment in em.elf.iter_segments():
        if segment['p_type']=='PT_GNU_RELRO':
            start=(em.BASE+segment['p_vaddr'])&~4095;end=(em.BASE+segment['p_vaddr']+segment['p_memsz']+4095)&~4095
            em.u.mem_protect(start,end-start,UC_PROT_READ)
    em.u.mem_protect(0x5000000,0x4000000,UC_PROT_READ|UC_PROT_WRITE)
    em.u.mem_protect(0x4000000,0x10000,UC_PROT_READ|UC_PROT_EXEC)
    em.u.mem_protect(0x4020000,0x10000,UC_PROT_READ|UC_PROT_EXEC)
device='12'*32;mode=os.environ.get('PROBE_MODE','nonroot')
fn=methods.get('challenge',methods.get('nLeaseChallenge'))
nonce=em.s(em.call(fn,(JNI,0,jstring(device),jstring(mode))))
print('challenge',nonce,flush=True)
proof=bytearray((root/'server-private/proof.bin').read_bytes())
proof[4:36]=bytes.fromhex(nonce);proof[36:68]=bytes.fromhex(device)
struct.pack_into('>QQ',proof,72,now+315360000,now)
proof[88:120]=hashlib.sha256((root/'payload-local.so').read_bytes()).digest()
if os.environ.get('ZERO_EXTRA'):
    proof[120:296]=bytes(176)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
signer=Ed25519PrivateKey.from_private_bytes(bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'))
signature=signer.sign(bytes(proof))
if os.environ.get('ACTUAL_PROOF'):
    proof=bytearray((root/('local-proof-'+mode+'.bin')).read_bytes())
    signature=(root/('local-signature-'+mode+'.bin')).read_bytes()
# Inspect the signed-lease verifier without replacing its behavior.
starts={x[0] for x in inventory['functions']};seen=set()
def trace(u,pc,size,_):
    if pc not in starts:return
    a=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(4)]
    if a[3]==304 and 0x5000000<a[2]<0x9000000:
        key=bytes(u.mem_read(a[1],32))
        if pc not in seen:
            seen.add(pc);print('lease verifier',hex(pc),'key',key.hex(),flush=True)
            (root/(Path(sys.argv[2]).stem+'-lease-verifier.json')).write_text(json.dumps({'function':pc,'public_key':key.hex()}))
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            # Sign the probe proof using an RFC 8032 test key and change only
            # the read-only public-key data in the emulator for this experiment.
            k=Ed25519PrivateKey.from_private_bytes(bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'))
            from cryptography.hazmat.primitives import serialization
            pub=k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
            u.mem_write(a[1],pub);u.mem_write(a[0],k.sign(bytes(proof)))
if os.environ.get('TRACE_LEASE'):em.u.hook_add(UC_HOOK_CODE,trace,begin=0x2b7a0,end=0x17d1e0)
accept=methods.get('accept',methods.get('nLeaseAccept'))
accepted=em.call(accept,(JNI,0,jarray(proof),jarray(signature)))
assert accepted==1,'native activation rejected'
print('accept',accepted,flush=True)
if methods.get('moduleHash')==0x4c284:
    print('deadline',struct.unpack('<Q',bytes(em.u.mem_read(0xa1410,8)))[0], 'state',bytes(em.u.mem_read(0xa14f8+0x1b0,8)).hex(),flush=True)
    print('gate',em.call(0x4c478),flush=True)
module=methods.get('moduleHash',methods.get('nLeaseModuleHash'))
p=em.call(module,(JNI,0));assert p,'module lease not available'
assert bytes(arrays[p][0])==hashlib.sha256((root/'payload-local.so').read_bytes()).digest()
print('module hash accepted',flush=True)
monotonic+=31
assert em.call(module,(JNI,0))==0,'expired lease accepted'
nonce=em.s(em.call(fn,(JNI,0,jstring(device),jstring(mode))))
proof[4:36]=bytes.fromhex(nonce)
signature=signer.sign(bytes(proof))
assert em.call(accept,(JNI,0,jarray(proof),jarray(signature)))==1
assert em.call(module,(JNI,0))!=0,'refreshed module lease unavailable'
bad=bytearray(signature);bad[7]^=1
assert em.call(accept,(JNI,0,jarray(proof),jarray(bad)))==0,'tampered signature accepted'
assert em.call(module,(JNI,0))==0,'revoked lease remained available'
print('expiry, refresh and tampering rejection passed',flush=True)
report={'library':Path(sys.argv[1]).name,'mode':mode,'strict_memory':bool(os.environ.get('STRICT_MEMORY')),'actual_java_proof':bool(os.environ.get('ACTUAL_PROOF')),'activation':True,'module_hash':True,'lease_expiry':True,'lease_refresh':True,'tampered_signature_rejected':True}
(root/('native-verification-'+Path(sys.argv[1]).stem+'-'+mode+'.json')).write_text(json.dumps(report,indent=2)+'\n')
