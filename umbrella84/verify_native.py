#!/usr/bin/env python3
"""Execute both actual ARM64 key comparisons and their activation state writes."""
import argparse, hashlib, io, json, re, struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_HOOK_CODE
from unicorn.arm64_const import *

BASE = 0x1000000
STATE = 0x4000000
STACK = 0x5000000
COMPARE = bytes.fromhex('c80240f9c90a40b91f011beb200158fa')

def inspect(path, key_start, accepted_key):
    data = path.read_bytes(); elf = ELFFile(io.BytesIO(data)); text = elf.get_section_by_name('.text')
    assert text['sh_addr'] == text['sh_offset']
    blocks = [m.start() for m in re.finditer(re.escape(COMPARE), data)]
    assert len(blocks) == 2, blocks
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for segment in elf.iter_segments():
        if segment['p_type'] != 'PT_LOAD':
            continue
        start = segment['p_vaddr'] & ~4095
        end = (segment['p_vaddr'] + segment['p_memsz'] + 4095) & ~4095
        flags = segment['p_flags']
        prot = (UC_PROT_READ if flags&4 else 0)|(UC_PROT_WRITE if flags&2 else 0)|(UC_PROT_EXEC if flags&1 else 0)
        u.mem_map(BASE+start, end-start, prot)
        u.mem_write(BASE+segment['p_vaddr'], segment.data())
    u.mem_map(STATE,4096,UC_PROT_READ|UC_PROT_WRITE)
    u.mem_map(STACK,4096,UC_PROT_READ|UC_PROT_WRITE)
    u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
    u.reg_write(UC_ARM64_REG_SP,STACK+2048)
    u.emu_start(BASE+key_start,BASE+key_start+48,count=100)
    expected = struct.pack('<QI',u.reg_read(UC_ARM64_REG_X27),u.reg_read(UC_ARM64_REG_X24))
    assert expected == accepted_key.encode()+b'\0', expected
    results=[]
    for block in blocks:
        branch = struct.unpack_from('<I',data,block+20)[0]
        assert branch&0xff00001f == 0x54000000
        displacement = (branch>>5)&0x7ffff
        if displacement&0x40000: displacement-=0x80000
        success = block+20+displacement*4
        end = BASE+success+60
        def completed(uc,address,size,user):
            if address == end: uc.emu_stop()
        hook = u.hook_add(UC_HOOK_CODE,completed)
        for key in ['@Umbreladlc','@Icon_Crack','','wrong','@icon_crack','@Icon_CrackX','@ICON_CRACK']:
            u.mem_write(STATE,bytes(4096)); u.mem_write(STATE+8,key.encode()+b'\0')
            u.reg_write(UC_ARM64_REG_X19,STATE); u.reg_write(UC_ARM64_REG_X22,STATE+8)
            u.emu_start(BASE+block,0,count=100)
            assert u.reg_read(UC_ARM64_REG_PC) == end
            active = struct.unpack('<I',bytes(u.mem_read(STATE,4)))[0] == 1
            assert active == (key == accepted_key),(path.name,hex(block),key,active)
            assert bool(u.mem_read(STATE+0x8a,1)[0]) == (not active)
            if active: assert bytes(u.mem_read(STATE+8,128)) == bytes(128)
            results.append({'entry':hex(block),'key':key,'accepted':active})
        u.hook_del(hook)
    return {'library_sha256':hashlib.sha256(data).hexdigest(),'comparison_paths':2,
            'native_activation_state_verified':True,'accepted_key':accepted_key,
            'android_runtime_stubbed':False,'isolated_native_blocks':True,
            'full_game_started':False,'cases':results}

def main():
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);a=p.parse_args();r=a.directory
    patches=json.loads((r/'native-patch-verification.json').read_text());report={}
    for role,old,new in [('root','libcfesp.so','libcfesp-icon.so'),
                         ('nonroot','apk-original/lib/arm64-v8a/libumbrella.so','libumbrella-icon.so')]:
        start=patches[role]['key_load_address']
        report[role]={'original':inspect(r/old,start,'@Umbreladlc'),
                      'patched':inspect(r/new,start,'@Icon_Crack')}
    (r/'native-auth-verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print('Actual ARM64 input-submit and activation-button paths passed for original and patched root/nonroot libraries')

if __name__=='__main__':main()
