#!/usr/bin/env python3
"""Apply a source-pinned, same-size key and contact patch to libAQR.so."""
import argparse,hashlib,json,struct
from pathlib import Path
from keystone import Ks,KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN
SOURCE='3968c47fb3897d4cc676693e16f5e2c69631006c03c011497a1faf372b8b66d7'
START=0x2c8b3c;LIMIT=0x2c8e00;BAD=0x2c8de0;CONFIG=0x2c8d20;DRAW=0x2c8df0

def patch(raw):
 assert hashlib.sha256(raw).hexdigest()==SOURCE,'Unexpected library version'
 config=json.loads(Path(__file__).with_name('runtime-config.json').read_text())
 runtime_json=json.dumps({'offsets':config['offsets']},separators=(',',':')).encode()
 ticket=config['draw_ticket'].encode()
 assert len(runtime_json)+1<=BAD-CONFIG and len(ticket)+1<=LIMIT-DRAW
 out=bytearray(raw);ks=Ks(KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN)
 def code(text,address):return bytes(ks.asm(text,address)[0])
 # Keep the existing thread, VM/context acquisition, mutex and native UI helpers.
 # x28 is the original thread tuple, whose key string is at +0x10.
 asm=f'''
 add x20, x28, #0x10
 adrp x8, 0x5c8000
 mov w9, #1
 strb w9, [x8, #0xae8]
 ldrb w8, [x20]
 tbnz w8, #0, heap_key
 lsr w2, w8, #1
 add x0, x20, #1
 b check_length
 heap_key:
 ldr x2, [x20, #8]
 ldr x0, [x20, #16]
 check_length:
 cmp x2, #11
 b.ne rejected
 adrp x1, 0x12d000
 add x1, x1, #0xe26
 mov x2, #11
 bl 0x52a900
 cbnz w0, rejected
 add x0, sp, #0xb8
 adrp x1, 0x2c8000
 add x1, x1, #0xd20
 mov w2, #{len(runtime_json)}
 bl 0x3647cc
 add x0, sp, #0xb8
 bl 0x2da0bc
 add x0, sp, #0xb8
 bl 0x52aa20
 adrp x0, 0x5c8000
 add x0, x0, #0xa88
 adrp x1, 0x2c8000
 add x1, x1, #0xdf0
 bl 0x52ab20
 adrp x0, 0x5c8000
 add x0, x0, #0xab8
 adrp x1, 0x131000
 add x1, x1, #0xf8d
 bl 0x52ab20
 ldr x0, [sp, #0x258]
 mov x1, x24
 mov x2, x20
 bl 0x292c6c
 adrp x8, 0x5b0000
 movz x9, #0x8ba6
 movk x9, #0xce4d, lsl #16
 movk x9, #0x1f92, lsl #32
 movk x9, #0xa7e3, lsl #48
 str x9, [x8, #0xd80]
 movz x9, #0xe6d1
 movk x9, #0x37a2, lsl #16
 movk x9, #0xb4f9, lsl #32
 movk x9, #0x51c8, lsl #48
 str x9, [x8, #0xd88]
 adrp x8, 0x5c8000
 strb wzr, [x8, #0xb6c]
 add x0, sp, #0xa0
 adrp x1, 0x12d000
 add x1, x1, #0xc67
 mov w2, #12
 bl 0x3647cc
 mov w22, #0
 b status
 rejected:
 adrp x8, 0x5c8000
 mov w9, #1
 strb w9, [x8, #0xb6c]
 add x0, x8, #0xa88
 adrp x1, 0x131000
 add x1, x1, #0xf8d
 bl 0x52ab20
 add x0, sp, #0xa0
 adrp x1, 0x2c8000
 add x1, x1, #0xde0
 mov w2, #11
 bl 0x3647cc
 mov w22, #1
 status:
 add x0, sp, #0xa0
 mov w1, w22
 bl 0x29a2cc
 add x0, sp, #0xa0
 bl 0x29fc50
 add x0, sp, #0xa0
 bl 0x52aa20
 adrp x8, 0x5c8000
 strb wzr, [x8, #0xae8]
 add x0, x8, #0xa60
 bl 0x52a9e0
 cbz x19, context_done
 ldr x0, [sp, #0x258]
 mov x1, x19
 ldr x8, [x0]
 ldr x8, [x8, #0xb8]
 blr x8
 context_done:
 ldr w21, [sp, #0x6c]
 tbnz w21, #0, done
 ldr x8, [x25]
 mov x0, x25
 ldr x8, [x8, #0x28]
 blr x8
 done:
 ldr x23, [sp, #0x58]
 b 0x2cc44c
 '''
 # The library's memcmp PLT is determined from its actual dynamic symbol table.
 from elftools.elf.elffile import ELFFile
 import io
 elf=ELFFile(io.BytesIO(raw));syms=elf.get_section_by_name('.dynsym')
 imports={syms.get_symbol(r['r_info_sym']).name:elf.get_section_by_name('.plt')['sh_addr']+32+16*i for i,r in enumerate(elf.get_section_by_name('.rela.plt').iter_relocations())}
 asm=asm.replace('bl 0x52a900',f"bl {imports['memcmp']}")
 body=code(asm,START);assert START+len(body)<=CONFIG
 out[START:LIMIT]=code('nop',START)*((LIMIT-START)//4)
 out[START:START+len(body)]=body
 out[BAD:BAD+12]=b'Invalid key\0'
 out[CONFIG:CONFIG+len(runtime_json)+1]=runtime_json+b'\0'
 out[DRAW:DRAW+len(ticket)+1]=ticket+b'\0'
 # The only text changes: key hint and contact in the existing instruction line.
 for address,old,new in [(0x12de26,b'Enter license key...',b'@Icon_Crack'),(0x12f196,b'Enter your key and tap Login',b'https://t.me/Icon_Crack')]:
  assert raw[address:address+len(old)+1]==old+b'\0';assert len(new)<=len(old)
  out[address:address+len(old)+1]=new+bytes(len(old)+1-len(new))
 assert raw[0x2a6ce0:0x2a6ce4]==code('mov w2, #0x1c',0x2a6ce0)
 out[0x2a6ce0:0x2a6ce4]=code('mov w2, #23',0x2a6ce0)
 # Restore the original runtime initializer before the original draw ticket.
 ticket_hash=0xcbf29ce484222325
 for value in ticket:ticket_hash=((ticket_hash^value)*0x100000001b3)&((1<<64)-1)
 assert ticket_hash==0x1e1394ec639b00a4
 # The renderer can reach this block before the game's function table exists.
 # Preserve its existing null-camera branch when the table itself is absent.
 guard=0x2c8e00;footer=0x2c8e40
 out[guard:0x2c9000]=code('nop',guard)*((0x2c9000-guard)//4)
 assert raw[0x1d2374:0x1d2378]==code('ldr x8, [x8, #0x598]',0x1d2374)
 out[0x1d2374:0x1d2378]=code(f'b {guard}',0x1d2374)
 guard_code=code('''
 ldr x8, [x8, #0x598]
 movk x9, #0x465d, lsl #16
 movk x9, #0x5d5c, lsl #32
 cbz x8, resume
 ldr x8, [x8]
 resume:
 b 0x1d2384
 ''',guard)
 assert guard+len(guard_code)<=footer
 out[guard:guard+len(guard_code)]=guard_code
 # Show live startup progress in the existing session footer. This makes a
 # missing game binding/camera observable without root or a computer.
 labels=[(0x2c8f40,b'Game module loading'),(0x2c8f60,b'Waiting for game world'),(0x2c8f80,b'Game world ready')]
 for address,label in labels:out[address:address+len(label)+1]=label+b'\0'
 footer_code=code('''
 stp x29, x30, [sp, #-32]!
 str x19, [sp, #16]
 mov x29, sp
 mov x19, x8
 adrp x9, 0x5c7000
 ldr x10, [x9, #0x598]
 cbz x10, module_loading
 ldr x10, [x10]
 cbz x10, module_loading
 ldrb w10, [x9, #0x764]
 tbz w10, #0, world_loading
 ldr x10, [x9, #0x768]
 cbz x10, world_loading
 adrp x1, 0x2c8000
 add x1, x1, #0xf80
 mov w2, #16
 b construct
 module_loading:
 adrp x1, 0x2c8000
 add x1, x1, #0xf40
 mov w2, #19
 b construct
 world_loading:
 adrp x1, 0x2c8000
 add x1, x1, #0xf60
 mov w2, #22
 construct:
 mov x0, x19
 bl 0x3647cc
 ldr x19, [sp, #16]
 ldp x29, x30, [sp], #32
 ret
 ''',footer)
 assert footer+len(footer_code)<=labels[0][0]
 out[footer:footer+len(footer_code)]=footer_code
 out[0x29c058:0x29c05c]=code(f'b {footer}',0x29c058)
 assert len(out)==len(raw)
 return bytes(out),{'source_sha256':SOURCE,'patched_sha256':hashlib.sha256(out).hexdigest(),'library_size':len(out),'auth_patch_start':hex(START),'auth_patch_end':hex(LIMIT),'auth_code_bytes':len(body),'key':'@Icon_Crack','telegram':'https://t.me/Icon_Crack','game_code_changed':False,'private_server_key_embedded':False,'draw_ticket_hash':hex(ticket_hash),'auth_state':hex(0xa7e31f92ce4d8ba6),'original_menu_ticket_verifier_preserved':True,'runtime_configuration_restored':True,'renderer_null_table_guard':hex(0x1d2374),'startup_footer':True,'helper_range':[hex(guard),hex(0x2c9000)],'game_callbacks_and_feature_handlers_changed':False}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('output',type=Path);p.add_argument('--report',type=Path,required=True);a=p.parse_args();result,report=patch(a.source.read_bytes());a.output.write_bytes(result);a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
