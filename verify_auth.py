#!/usr/bin/env python3
"""Execute the patched ARM64 worker and original auth UI using an Android fixture."""
import argparse,hashlib,json,struct
from pathlib import Path
from unicorn import UC_HOOK_CODE
from native_image import Image,BASE,HOST
from unicorn.arm64_const import *
RUNTIME=json.loads(Path(__file__).with_name('runtime-config.json').read_text())
EXPECTED_TICKET=RUNTIME['draw_ticket']
EXPECTED_OFFSETS=[int(RUNTIME['offsets'][n],16) for n in ['PlayerManager_get_health','HitBox_IsVisible','Camera_get_main','NetworkBehaviour_get_isLocalPlayer']]
JNI=HOST+0x200000;JVT=JNI+0x1000;VM=JNI+0x2000;VMT=JNI+0x3000;ACT=JNI+0x4000;TUP=JNI+0x5000
class Android(Image):
 def __init__(self,path,attached=True,context=True):
  super().__init__(path);self.mutex=[];self.init();self.attached=attached;self.saved=[];self.detach=0;self.network=[];self.mutex=[];self.methods={};self.strings={};self.calls=[]
  self.u.mem_write(JNI,struct.pack('<Q',JVT));self.u.mem_write(VM,struct.pack('<Q',VMT))
  for off in range(0,0x780,8):
   a=HOST+0x8000+off*2;self.names[a]='JNI:'+hex(off);self.u.mem_write(a,bytes.fromhex('c0035fd6'));self.u.mem_write(JVT+off,struct.pack('<Q',a))
  for idx,(off,n) in enumerate([(0x30,'GetEnv'),(0x20,'Attach'),(0x28,'Detach')]):
   a=HOST+0xa000+idx*16;self.names[a]='VM:'+n;self.u.mem_write(a,bytes.fromhex('c0035fd6'));self.u.mem_write(VMT+off,struct.pack('<Q',a))
  self.u.mem_write(BASE+0x5c7580,struct.pack('<Q',VM))
  self.u.mem_write(BASE+0x5c7588,struct.pack('<Q',ACT if context else 0))
  # Verify these are the exact VM/context globals reached by the source GOT.
  self.u.mem_write(int.from_bytes(self.u.mem_read(BASE+0x55ce38,8),'little'),struct.pack('<Q',VM))
  self.u.mem_write(int.from_bytes(self.u.mem_read(BASE+0x55ce40,8),'little'),struct.pack('<Q',ACT if context else 0))
  self.u.hook_add(UC_HOOK_CODE,self.save_entry,begin=BASE+0x292c6c,end=BASE+0x292c6c)
 def save_entry(self,u,pc,size,data):self.saved.append(self.string(self.reg(2)))
 def external(self,u,pc,size,data):
  n=self.names[pc];a=[self.reg(i) for i in range(5)]
  if n.startswith('VM:'):
   if n=='VM:GetEnv':
    if self.attached:u.mem_write(a[1],struct.pack('<Q',JNI));self.ret()
    else:self.ret((1<<64)-2)
   elif n=='VM:Attach':u.mem_write(a[1],struct.pack('<Q',JNI));self.ret()
   else:self.detach+=1;self.ret()
  elif n.startswith('JNI:'):
   off=int(n[4:],0);self.calls.append((hex(off),a[1:]))
   if off==0x108:
    v=self.malloc(16);self.methods[v]=self.cstr(a[2]).decode();self.ret(v)
   elif off==0x538:
    v=self.malloc(16);self.strings[v]=self.cstr(a[1]);self.ret(v)
   elif off in [0x118,0x120,0x110,0x398]:
    self.ret(self.malloc(16))
   elif off in [0x30,0xf8,0xa8,0x388]:self.ret(ACT)
   elif off in [0x720,0x88,0xb8,0x1f0,0x1f8,0x1e8,0x28]:self.ret()
   else:raise AssertionError(('unexpected JNI call',hex(off)))
  elif n in ['_ZNSt6__ndk15mutex4lockEv','_ZNSt6__ndk15mutex6unlockEv','pthread_mutex_lock','pthread_mutex_unlock']:
   self.mutex.extend([n] if a[0]==BASE+0x5c8a60 else []);self.ret()
  elif n in ['connect','send','recv','socket','getaddrinfo'] or n.startswith('curl_'):
   self.network.append(n);raise AssertionError(('network invoked',n))
  else:super().external(u,pc,size,data)
 def run(self,key,heap=False):
  if heap:
   p=self.malloc(len(key)+1);self.u.mem_write(p,key+b'\0');self.u.mem_write(TUP+0x10,struct.pack('<QQQ',33,len(key),p))
  else:self.putstr(TUP+0x10,key)
  self.putstr(TUP+0x28,b'fixture-device')
  self.u.mem_write(BASE+0x5c8b6c,b'\x01')
  self.call(0x2c86e8,TUP)
  state={'required':self.u.mem_read(BASE+0x5c8b6c,1)[0],'busy':self.u.mem_read(BASE+0x5c8ae8,1)[0],'status':self.string(BASE+0x5c8aa0).decode(),'draw_ticket':self.string(BASE+0x5c8a88).decode(),'saved': [x.decode() for x in self.saved], 'detach':self.detach,'network_calls':len(self.network),'runtime_offsets':list(struct.unpack('<QQQQ',self.u.mem_read(BASE+0x5c7688,32))),'runtime_ready':self.u.mem_read(BASE+0x5c76a8,1)[0]}
  return state

class MonitorAndroid(Android):
 def __init__(self,path):self.virtual_seconds=0;super().__init__(path)
 def external(self,u,pc,size,data):
  n=self.names[pc]
  if n=='sleep':self.virtual_seconds+=self.reg(0);self.ret()
  elif n=='_exit' or n=='syscall' and self.reg(0)!=178:raise AssertionError(('unexpected process termination',n,self.reg(0)))
  else:super().external(u,pc,size,data)

def menu_render_guard(m):
 # Execute the unchanged renderer's comparison against its own auth constant.
 state=m.call(0x29b324)
 m.u.reg_write(UC_ARM64_REG_X0,state)
 m.u.emu_start(BASE+0x1d21b0,BASE+0x1d220c,count=100)
 return bool(int.from_bytes(m.u.mem_read(m.u.reg_read(UC_ARM64_REG_SP)+0x18,4),'little'))

def menu_body_guard(m):
 # Run the real menu body entry, including its real state getter; stop at the
 # first post-auth instruction or the normal rejection path before graphics.
 seen=[]
 def gate(u,pc,size,data):
  seen.append(pc==BASE+0x1d2d18);u.emu_stop()
 h1=m.u.hook_add(UC_HOOK_CODE,gate,begin=BASE+0x1d2d18,end=BASE+0x1d2d18)
 h2=m.u.hook_add(UC_HOOK_CODE,gate,begin=BASE+0x1d6370,end=BASE+0x1d6370)
 from native_image import STACK,STOP
 m.u.reg_write(UC_ARM64_REG_SP,STACK);m.u.reg_write(UC_ARM64_REG_LR,STOP)
 m.u.reg_write(UC_ARM64_REG_X0,0);m.u.reg_write(UC_ARM64_REG_X1,1920);m.u.reg_write(UC_ARM64_REG_X2,1080)
 try:m.u.emu_start(BASE+0x1d2c6c,STOP,count=10000)
 finally:m.u.hook_del(h1);m.u.hook_del(h2)
 assert len(seen)==1,'menu guard did not reach a decision'
 return seen[0]

def main():
 p=argparse.ArgumentParser();p.add_argument('library',type=Path);p.add_argument('--report',type=Path);p.add_argument('--previous-library',type=Path);a=p.parse_args();results=[]
 m=Android(a.library)
 # curl/runtime initialization is an unchanged platform dependency.
 m.u.hook_add(UC_HOOK_CODE,lambda u,pc,size,data:m.ret(),begin=BASE+0x36501c,end=BASE+0x36501c)
 m.call(0x2a6c2c)
 assert m.string(BASE+0x5c8aa0)==b'https://t.me/Icon_Crack'
 assert m.u.mem_read(BASE+0x5c8b6c,1)==b'\x01'
 results.append({'case':'initial-contact-prompt','contact':'https://t.me/Icon_Crack'})
 cases=[(b'@Icon_Crack',False,True,True),(b'@Icon_Crack',True,True,True),(b'@Icon_Crack',False,False,True),(b'@Icon_Crac',False,True,False),(b'@icon_crack',False,True,False),(b'@Icon_Crackx',False,True,False),(b'',False,True,False),(b'x'*4096,True,True,False)]
 for key,heap,attached,valid in cases:
  m=Android(a.library,attached=attached);s=m.run(key,heap)
  assert s['busy']==0,s
  assert s['required']==(0 if valid else 1),s
  assert s['saved']==(['@Icon_Crack'] if valid else []),s
  assert s['status']==('Key verified' if valid else 'Invalid key'),s
  assert s['detach']==(0 if attached else 1),s
  assert s['network_calls']==0,s
  assert m.mutex==['pthread_mutex_lock','pthread_mutex_unlock'],m.mutex
  if valid:
   assert set(m.methods.values())=={'getSharedPreferences','edit','putString','apply'}
   assert b'@Icon_Crack' in m.strings.values() and b'license_key' in m.strings.values()
   assert s['draw_ticket']==EXPECTED_TICKET and s['runtime_offsets']==EXPECTED_OFFSETS and s['runtime_ready']==1
   assert m.call(0x29b324)==0xa7e31f92ce4d8ba6
   assert menu_render_guard(m) and menu_body_guard(m)
  else:
   assert not menu_render_guard(m) and not menu_body_guard(m)
  if valid:
   # Execute the original authentication renderer: after success it returns
   # without entering ImGui, rather than displaying a second login/spinner.
   m.call(0x2a0adc,count=200000)
  results.append({'input':key.decode() if len(key)<30 else '4096-byte invalid key','heap_string':heap,'already_attached':attached,'valid':valid,**s})
 for attached in [True,False]:
  m=Android(a.library,attached=attached,context=False);s=m.run(b'@Icon_Crack')
  assert s['required']==0 and s['busy']==0 and s['saved']==['@Icon_Crack']
  assert s['detach']==(0 if attached else 1)
  s['case']='application-context-fallback';s['already_attached']=attached;results.append(s)
 # Failed entry followed by successful retry in the same native instance.
 m=Android(a.library);m.run(b'wrong');s=m.run(b'@Icon_Crack');assert s['required']==0 and s['draw_ticket']==EXPECTED_TICKET and s['busy']==0;s['case']='invalid-then-valid';results.append(s)
 monitor=MonitorAndroid(a.library);monitor.run(b'@Icon_Crack')
 for _ in range(30):
  monitor.call(0x1ca06c,count=200000)
  assert monitor.call(0x29b324)==0xa7e31f92ce4d8ba6
 assert monitor.virtual_seconds==30
 report={'library_sha256':hashlib.sha256(a.library.read_bytes()).hexdigest(),'cases_passed':len(results),'cases':results,'phone_tested':False,'original_monitor_virtual_seconds':monitor.virtual_seconds,'real_renderer_and_menu_body_auth_guards_verified':True,'original_runtime_parser_executed_and_configuration_verified':True}
 if a.previous_library:
  old=Android(a.previous_library);state=old.run(b'@Icon_Crack')
  assert state['required']==0
  assert state['runtime_offsets']==[0,0,0,0] and state['runtime_ready']==0
  report['previous_build_missing_runtime_reproduced']={'message':state['status'],'main_menu_authorized':menu_render_guard(old),'runtime_offsets':state['runtime_offsets'],'runtime_ready':False}
 if a.report:a.report.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'cases_passed':len(results),'library_sha256':report['library_sha256']},indent=2))
if __name__=='__main__':main()
