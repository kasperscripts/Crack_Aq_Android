"""Add the fixed-key path while retaining the module's original auth callbacks."""
import hashlib,json,struct
from pathlib import Path
from keystone import Ks,KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN
ROOT=Path(__file__).parent;original=ROOT/'cf-menu.dylib';raw=bytearray(original.read_bytes())
assert hashlib.sha256(raw).hexdigest()=='567199bfb455580891dc65d880985ba84bc27cef6dcdc24a3c598ed996de6043'
assert not any(raw[0x127580:0x128000])
ks=Ks(KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN);patches=[];cursor=0x127b00
def put(a,data,label):
 raw[a:a+len(data)]=data;patches.append({'address':hex(a),'size':len(data),'label':label})
def string(value):
 global cursor
 address=cursor;data=value.encode()+b'\0';put(address,data,'literal');cursor+=len(data);return address
def ptr(r,a):return f'adrp {r},#{a&~4095}; add {r},{r},#{a&4095}'
def load(r,a):return f'adrp {r},#{a&~4095}; ldr {r},[{r},#{a&4095}]'
def asm(a,text,label,limit):
 data=bytes(ks.asm(text,a)[0]);assert a+len(data)<=limit,(label,len(data));put(a,data,label)
key=string('@Icon_Crack');display=string('@Icon_Crack бай бай жирный')
profile={'token':'@Icon_Crack','plan':'Premium','expires_at':4102444799,'valid':True}
json_address=string(json.dumps(profile,separators=(',',':')))
url=string('https://t.me/Icon_Crack');open_selector=string('openURL:options:completionHandler:');register_symbol=string('sel_registerName');signature=string('v8@?0')

asm(0x127580,f'''
 stp x29,x30,[sp,#-96]!
 stp x19,x20,[sp,#16]
 stp x21,x22,[sp,#32]
 mov x19,x0
 mov x20,x1
 mov x21,x2
 {load('x1',0x131758)}
 {ptr('x2',0x12a3a0)}
 mov x0,x20
 bl #0xb9124
 cbz x0,token
 {load('x1',0x1316c8)}
 bl #0xb9124
 {ptr('x1',key)}
 bl #0xb90a0
 cbz w0,accepted
token:
 {load('x1',0x131758)}
 {ptr('x2',0x12a320)}
 mov x0,x20
 bl #0xb9124
 cbz x0,fallback
 {load('x1',0x1316c8)}
 bl #0xb9124
 {ptr('x1',key)}
 bl #0xb90a0
 cbnz w0,fallback
accepted:
 {load('x0',0x131a20)}
 {load('x1',0x131628)}
 {ptr('x2',json_address)}
 bl #0xb9124
 {load('x1',0x1311a8)}
 mov x2,#4
 bl #0xb9124
 mov x2,x0
 {load('x0',0x131a68)}
 {load('x1',0x131678)}
 mov x3,#0
 mov x4,#0
 bl #0xb9124
 mov x2,x0
 mov x0,x21
 mov x1,#200
 mov x3,#0
 ldr x8,[x21,#16]
 blr x8
 ldp x21,x22,[sp,#32]
 ldp x19,x20,[sp,#16]
 ldp x29,x30,[sp],#96
 ret
fallback:
 mov x0,x19
 mov x1,x20
 mov x2,x21
 ldp x21,x22,[sp,#32]
 ldp x19,x20,[sp,#16]
 ldp x29,x30,[sp],#96
 sub sp,sp,#0x90
 b #0x5c48
''','fixed-key network gate',0x127740)

brand=f'''
 stp x29,x30,[sp,#-64]!
 stp x19,x20,[sp,#16]
 str x0,[sp,#32]
 str x8,[sp,#40]
 mov x20,x8
 ldrsb w9,[x0,#23]
 ldr x10,[x0]
 cmp w9,#0
 csel x19,x10,x0,lt
'''
for address in [0xd3523,0xd353e,0xd3556]:brand+=f'mov x0,x19; {ptr("x1",address)}; bl #0xb90a0; cbz w0,replace\n'
brand+='''
 ldr x0,[sp,#32]
 ldr x8,[sp,#40]
 ldp x19,x20,[sp,#16]
 ldp x29,x30,[sp],#64
 stp x22,x21,[sp,#-48]!
 b #0x319e4
replace:
 stp xzr,xzr,[x20]
 str xzr,[x20,#16]
 mov x0,x20
'''+ptr('x1',display)+'''; bl #0xb916c
 ldp x19,x20,[sp,#16]
 ldp x29,x30,[sp],#64
 ret
'''
asm(0x127740,brand,'visible attribution translator',0x127840)

asm(0x127840,f'''
 stp x29,x30,[sp,#-96]!
 stp x19,x20,[sp,#16]
 mov x0,x1
 bl #0x92404
 cbz w0,done
 {ptr('x19',0x139800)}
 stp xzr,xzr,[x19]
 mov x8,#32
 str x8,[x19,#8]
 {ptr('x8',signature)}
 str x8,[x19,#16]
 {load('x8',0x128008)}
 str x8,[sp,#48]
 mov w8,#0x40000000
 str w8,[sp,#56]
 str wzr,[sp,#60]
 {ptr('x8',0x127940)}
 str x8,[sp,#64]
 str x19,[sp,#72]
 {load('x0',0x128068)}
 add x1,sp,#48
 bl #0xb9220
done:
 ldp x19,x20,[sp,#16]
 ldp x29,x30,[sp],#96
 ret
''','clickable Telegram footer',0x127940)

asm(0x127940,f'''
 stp x29,x30,[sp,#-64]!
 stp x19,x20,[sp,#16]
 stp x21,x22,[sp,#32]
 mov x0,#-2
 {ptr('x1',register_symbol)}
 bl #0xb90ac
 cbz x0,done
 mov x19,x0
 {ptr('x0',open_selector)}
 blr x19
 mov x22,x0
 {load('x0',0x131ad8)}
 {load('x1',0x131370)}
 bl #0xb9124
 mov x19,x0
 {load('x0',0x131a20)}
 {load('x1',0x131628)}
 {ptr('x2',url)}
 bl #0xb9124
 mov x2,x0
 {load('x0',0x131a58)}
 {load('x1',0x131130)}
 bl #0xb9124
 mov x20,x0
 {load('x0',0x131a38)}
 {load('x1',0x1318b0)}
 bl #0xb9124
 mov x3,x0
 mov x0,x19
 mov x1,x22
 mov x2,x20
 mov x4,#0
 bl #0xb9124
done:
 ldp x21,x22,[sp,#32]
 ldp x19,x20,[sp,#16]
 ldp x29,x30,[sp],#64
 ret
''','open Telegram on main queue',0x127b00)

asm(0x5c44,'b #0x127580','request entry trampoline',0x5c48)
asm(0x319e0,'b #0x127740','translation entry trampoline',0x319e4)
asm(0x3073c,'bl #0x127840','Telegram footer entry',0x30740)
assert cursor<0x128000
output=ROOT/'cf-menu-icon.dylib';output.write_bytes(raw)
(ROOT/'patch-map.json').write_text(json.dumps({'source_sha256':hashlib.sha256(original.read_bytes()).hexdigest(),'output_sha256':hashlib.sha256(raw).hexdigest(),'key':'@Icon_Crack','display':'@Icon_Crack бай бай жирный','profile':profile,'patches':patches},indent=2)+'\n')
print('Patched module; literals end',hex(cursor),'of 0x128000')
