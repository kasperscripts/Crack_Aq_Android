import os,sys,struct,hashlib,json
from pathlib import Path
root=Path(__file__).parent
os.environ.setdefault('ELF_BASE','0x1000000')
ns={'__file__':str(root/'probe_lease.py'),'__name__':'native_fixture'}
exec(compile((root/'probe_lease.py').read_text().split("device='12'*32;")[0],str(root/'probe_lease.py'),'exec'),ns)
em=ns['em'];JNI=ns['JNI'];jstring=ns['jstring'];jarray=ns['jarray'];methods=ns['methods'];mode=os.environ.get('PROBE_MODE','nonroot')
assert em.BASE!=0
out=em.alloc(64)
assert em.call(0x1325cc,(out,))==1
actual=bytes(em.u.mem_read(out,64))
expected=hashlib.sha512(b''.join(s.data() for s in em.elf.iter_segments() if s['p_type']=='PT_LOAD' and not s['p_flags']&2)).digest()
assert actual==expected
print('Native mapped-image digest matches actual non-writable PT_LOAD contents',flush=True)
# This flag enables the integrity branch used after the game backend starts.
em.u.mem_write(em.BASE+0x1e27b4,b'\1')
nonce=em.s(em.call(methods['challenge'],(JNI,0,jstring('12'*32),jstring(mode))))
revision='v4-' if os.environ.get('EXPECT_V4_FAILURE') else ''
proof=(root/('local-proof-'+revision+mode+'.bin')).read_bytes();sig=(root/('local-signature-'+revision+mode+'.bin')).read_bytes()
assert proof[4:36]==bytes.fromhex(nonce)
result=em.call(methods['accept'],(JNI,0,jarray(proof),jarray(sig)))
if os.environ.get('EXPECT_V4_FAILURE'):
    assert proof[120:184]==bytes(64)
    assert result==0
    print('v4 reproduces post-startup invalid_proof with image check enabled',flush=True)
else:
    assert proof[120:184]==actual
    assert result==1,'loaded-image lease rejected'
    pointer=em.call(methods['moduleHash'],(JNI,0));assert pointer
    print('Loaded game backend accepts signed lease and exposes module permissions',flush=True)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    signer=Ed25519PrivateKey.from_private_bytes(bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'))
    ns['monotonic']+=31
    assert em.call(methods['moduleHash'],(JNI,0))==0,'expired lease remained active'
    nonce=em.s(em.call(methods['challenge'],(JNI,0,jstring('12'*32),jstring(mode))))
    proof=bytearray(proof);proof[4:36]=bytes.fromhex(nonce);sig=signer.sign(bytes(proof))
    assert em.call(methods['accept'],(JNI,0,jarray(proof),jarray(sig)))==1
    assert em.call(methods['moduleHash'],(JNI,0))!=0,'refresh lost permissions'
    nonce=em.s(em.call(methods['challenge'],(JNI,0,jstring('12'*32),jstring(mode))))
    proof[4:36]=bytes.fromhex(nonce);sig=signer.sign(bytes(proof))
    bad=bytearray(sig);bad[7]^=1
    assert em.call(methods['accept'],(JNI,0,jarray(proof),jarray(bad)))==0,'tampered signature accepted'
    assert em.call(methods['moduleHash'],(JNI,0))==0,'invalid proof retained permissions'
    nonce=em.s(em.call(methods['challenge'],(JNI,0,jstring('12'*32),jstring(mode))))
    proof[4:36]=bytes.fromhex(nonce);sig=signer.sign(bytes(proof))
    assert em.call(methods['accept'],(JNI,0,jarray(proof),jarray(sig)))==1
    nonce=em.s(em.call(methods['challenge'],(JNI,0,jstring('12'*32),jstring(mode))))
    proof[4:36]=bytes.fromhex(nonce);sig=signer.sign(bytes(proof))
    address=em.BASE+0x50000;original=bytes(em.u.mem_read(address,1));em.u.mem_write(address,bytes([original[0]^1]))
    assert em.call(methods['accept'],(JNI,0,jarray(proof),jarray(sig)))==0,'modified native image accepted'
    em.u.mem_write(address,original)
    report={'library':Path(sys.argv[1]).name,'mode':mode,'load_base':hex(em.BASE),'strict_memory':bool(os.environ.get('STRICT_MEMORY')),'actual_dex_proof':True,'mapped_image_digest_verified':True,'post_start_activation':True,'module_permissions':True,'lease_expiry':True,'lease_refresh':True,'tampered_signature_rejected':True,'modified_native_image_rejected':True,'android_task_directory_unavailable':True,'phone_execution_tested':False}
    (root/('native-live-image-'+mode+'.json')).write_text(json.dumps(report,indent=2)+'\n')
    print('Post-start expiry, refresh, signature rejection and image-integrity checks passed',flush=True)
