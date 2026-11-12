import hashlib,json,struct
from pathlib import Path
from keystone import Ks,KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN

ROOT=Path(__file__).parent
ORIGINAL=ROOT/'YouAreRetardBro.dylib'
GATE=0x3e6e70
LOCAL=0x3e6f40
FIELD=0x3e7240
DATA=0x3e7300
# dyld makes __DATA_CONST read-only after fixups. Keep runtime descriptors in
# unused, writable __DATA VM padding after the last section (end 0x491aa1).
DESCRIPTOR=0x491b00
ks=Ks(KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN)
raw=bytearray(ORIGINAL.read_bytes())
assert hashlib.sha256(raw).hexdigest()=='d0999187325b5a027997dfe01e9b3ed57e6f4778ce0af5ea1c7937e68a4971bf'
assert not any(raw[GATE:0x3e8000])
patches=[];cursor=DATA
def put(a,data,label):
    before=bytes(raw[a:a+len(data)]);raw[a:a+len(data)]=data
    patches.append({'address':hex(a),'size':len(data),'label':label,'before_sha256':hashlib.sha256(before).hexdigest(),'after_sha256':hashlib.sha256(data).hexdigest()})
def string(s):
    global cursor
    a=cursor;data=s.encode()+b'\0';put(a,data,'literal');cursor+=len(data);return a
def ptr(reg,a):return f'adrp {reg},#{a&~4095}; add {reg},{reg},#{a&4095}'
def load(reg,a):return f'adrp {reg},#{a&~4095}; ldr {reg},[{reg},#{a&4095}]'
def asm(a,s,label,limit=None):
    out=bytes(ks.asm(s,a)[0]);assert limit is None or a+len(out)<=limit,(hex(a),len(out));put(a,out,label)

key=string('@Icon_Crack');signature=string('v8@?0')
profile={'nonce':'Icon_Crack_local','error':'Try again!','draw':'sX9AQR3','message':'Key verified successfully','offsets':{'PlayerManager_get_health':'0x50B9CA4','HitBox_IsVisible':'0x4F83520','Camera_get_main':'0xCBC0DC4','NetworkBehaviour_get_isLocalPlayer':'0xBB9B81C'},'expires_at':'2099-12-31 23:59:59'}
profile_address=string(json.dumps(profile,separators=(',',':')))
fields={k:string(k) for k in ['nonce','error','draw','message','offsets','expires_at']}
cursor=0x3e7900
display_name=string('@Icon_Crack бай бай жирный')
auth_title=string('AUTH: @Icon_Crack бай бай жирный')
telegram_title=string('Telegram: @Icon_Crack бай бай жирный')
telegram_url=string('https://t.me/Icon_Crack')
ui_class=string('UIApplication');url_class=string('NSURL');dictionary_class=string('NSDictionary')
sel_shared=string('sharedApplication');sel_open=string('openURL:options:completionHandler:');sel_dictionary=string('dictionary')

def key_gate(a,mode,original_instruction,fallthrough):
 asm(a,f'''
 stp x29,x30,[sp,#-64]!
 mov x29,sp
 stp x0,x1,[sp,#16]
 str x2,[sp,#32]
 {load('x0',0x46b198)}
 {load('x1',0x46a2d8)}
 {ptr('x2',key)}
 bl #0x1cda78
 mov x2,x0
 ldr x0,[sp,#32]
 {load('x1',0x46aa10)}
 bl #0x1cda78
 cbz w0,fallback
 ldr x0,[sp,#24]
 ldr x1,[sp,#32]
 mov x2,#{mode}
 bl #{LOCAL}
 ldp x29,x30,[sp],#64
 ret
fallback:
 ldp x0,x1,[sp,#16]
 ldr x2,[sp,#32]
 ldp x29,x30,[sp],#64
 {original_instruction}
 b #{fallthrough}
''','fixed key entry',LOCAL if mode==0 else 0x3e7b00)
key_gate(GATE,0,'stp x28,x27,[sp,#-96]!',0x3126c)
key_gate(0x3e7a00,1,'stp d9,d8,[sp,#-112]!',0x3c770)

body=f'''
 stp x29,x30,[sp,#-176]!
 mov x29,sp
 stp x19,x20,[sp,#16]
 stp x21,x22,[sp,#32]
 mov x19,x0
 mov x22,x2
 str x1,[sp,#48]
 mov x2,x1
 {load('x1',0x46a780)}
 bl #0x1cda78
 {load('x0',0x46b198)}
 {load('x1',0x46a2d8)}
 {ptr('x2',profile_address)}
 bl #0x1cda78
 {load('x1',0x46a360)}
 mov x2,#4
 bl #0x1cda78
 mov x2,x0
 {load('x0',0x46b230)}
 {load('x1',0x46a700)}
 mov x3,#0
 mov x4,#0
 bl #0x1cda78
 mov x20,x0
 cbnz x22,second_descriptor
 {ptr('x21',DESCRIPTOR)}
 mov x8,#96
 {ptr('x9',0x3b0a0)}
 {ptr('x10',0x3b0f8)}
 {ptr('x11',0x383e8)}
 mov x12,#0x800
 b make_descriptor
second_descriptor:
 {ptr('x21',DESCRIPTOR+128)}
 mov x8,#104
 {ptr('x9',0x47de8)}
 {ptr('x10',0x47e48)}
 {ptr('x11',0x453b8)}
 mov x12,#0x900
make_descriptor:
 stp xzr,x8,[x21]
 stp x9,x10,[x21,#16]
 {ptr('x8',signature)}
 stp x8,x12,[x21,#32]
 {load('x8',0x3e8028)}
 str x8,[sp,#64]
 mov w8,#0xc2000000
 str w8,[sp,#72]
 str wzr,[sp,#76]
 str x11,[sp,#80]
 str x21,[sp,#88]
 str x19,[sp,#112]
'''
for name,slots in [('nonce',[96,104]),('error',[120]),('draw',[128]),('message',[136]),('expires_at',[152])]:
    body+=f"mov x0,x20; {ptr('x1',fields[name])}; bl #{FIELD}; "+'; '.join(f'str x0,[sp,#{slot}]' for slot in slots)+'\n'
body+=f'''
 mov x0,x20
 {ptr('x1',fields['offsets'])}
 bl #{FIELD}
 cbnz x22,second_captures
 str x0,[sp,#144]
 b dispatch_result
second_captures:
 str x0,[sp,#160]
 ldr x8,[sp,#48]
 str x8,[sp,#144]
dispatch_result:
 {load('x0',0x3e8020)}
 add x1,sp,#64
 bl #0x1cdaa8
 ldp x21,x22,[sp,#32]
 ldp x19,x20,[sp,#16]
 ldp x29,x30,[sp],#176
 ret
'''
asm(LOCAL,body,'original SDK success block',FIELD)
asm(FIELD,f'''
 stp x29,x30,[sp,#-32]!
 str x0,[sp,#16]
 mov x2,x1
 {load('x0',0x46b198)}
 {load('x1',0x46a2d8)}
 bl #0x1cda78
 mov x2,x0
 ldr x0,[sp,#16]
 {load('x1',0x46af40)}
 bl #0x1cda78
 ldp x29,x30,[sp],#32
 ret
''','dictionary field',DATA)
asm(0x31268,f'b #{GATE}','auth trampoline')
asm(0x3c76c,'b #0x3e7a00','repeat auth trampoline')
for a in [0x4f7f4,0x4f920]:asm(a,ptr('x0',display_name),'menu attribution')
asm(0x538bc,ptr('x0',telegram_title),'Telegram section label')
asm(0x56690,ptr('x0',auth_title),'authentication attribution')
asm(0x538dc,'bl #0x3e7500','Telegram button wrapper')
asm(0x3e7500,f'''
 stp x29,x30,[sp,#-112]!
 stp x19,x20,[sp,#16]
 bl #0x5e964
 mov x19,x0
 {ptr('x0',telegram_title)}
 stp wzr,wzr,[sp,#32]
 add x1,sp,#32
 bl #0x1bc6f0
 cbz w0,done
 {ptr('x20',DESCRIPTOR+48)}
 stp xzr,xzr,[x20]
 mov x8,#32
 str x8,[x20,#8]
 {ptr('x8',signature)}
 str x8,[x20,#16]
 {load('x8',0x3e8028)}
 str x8,[sp,#64]
 mov w8,#0x40000000
 str w8,[sp,#72]
 str wzr,[sp,#76]
 {ptr('x8',0x3e7640)}
 str x8,[sp,#80]
 str x20,[sp,#88]
 {load('x0',0x3e8020)}
 add x1,sp,#64
 bl #0x1cdaa8
done:
 mov x0,x19
 ldp x19,x20,[sp,#16]
 ldp x29,x30,[sp],#112
 ret
''','Telegram button',0x3e7640)
asm(0x3e7640,f'''
 stp x29,x30,[sp,#-64]!
 stp x19,x20,[sp,#16]
 stp x21,x22,[sp,#32]
 {ptr('x0',ui_class)}
 bl #0x1cdf7c
 mov x19,x0
 {ptr('x0',sel_shared)}
 bl #0x3e77c0
 mov x1,x0
 mov x0,x19
 bl #0x1cda78
 mov x19,x0
 {load('x0',0x46b198)}
 {load('x1',0x46a2d8)}
 {ptr('x2',telegram_url)}
 bl #0x1cda78
 mov x21,x0
 {ptr('x0',url_class)}
 bl #0x1cdf7c
 {load('x1',0x46a698)}
 mov x2,x21
 bl #0x1cda78
 mov x20,x0
 {ptr('x0',dictionary_class)}
 bl #0x1cdf7c
 mov x21,x0
 {ptr('x0',sel_dictionary)}
 bl #0x3e77c0
 mov x1,x0
 mov x0,x21
 bl #0x1cda78
 mov x21,x0
 {ptr('x0',sel_open)}
 bl #0x3e77c0
 mov x1,x0
 mov x0,x19
 mov x2,x20
 mov x3,x21
 mov x4,#0
 bl #0x1cda78
 ldp x21,x22,[sp,#32]
 ldp x19,x20,[sp,#16]
 ldp x29,x30,[sp],#64
 ret
''','open Telegram on main queue',0x3e77c0)
asm(0x3e77c0,f'''
 stp x29,x30,[sp,#-16]!
 mov x2,x0
 {load('x0',0x46b198)}
 {load('x1',0x46a2d8)}
 bl #0x1cda78
 bl #0x1cdd60
 ldp x29,x30,[sp],#16
 ret
''','selector helper',0x3e7900)
assert cursor<=0x3e7a00, 'UI literals must not overlap the repeat-login gate'
(ROOT/'YouAreRetardBro-icon.dylib').write_bytes(raw)
(ROOT/'patch-map.json').write_text(json.dumps({'patches':patches,'profile':profile,'input_sha256':hashlib.sha256(ORIGINAL.read_bytes()).hexdigest(),'output_sha256':hashlib.sha256(raw).hexdigest()},indent=2)+'\n')
print('Patched',len(patches),'regions; code/data cave ends',hex(cursor))
