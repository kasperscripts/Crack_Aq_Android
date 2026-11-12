#!/usr/bin/env python3
"""Execute the patched ARM64 worker and original auth UI using an Android fixture."""
import argparse,hashlib,json,struct
from pathlib import Path
from unicorn import UC_HOOK_CODE
from native_image import Image,BASE,HOST
from unicorn.arm64_const import *
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
  state={'required':self.u.mem_read(BASE+0x5c8b6c,1)[0],'busy':self.u.mem_read(BASE+0x5c8ae8,1)[0],'status':self.string(BASE+0x5c8aa0).decode(),'error':self.string(BASE+0x5c8a88).decode(),'saved': [x.decode() for x in self.saved], 'detach':self.detach,'network_calls':len(self.network)}
  return state

def main():
 p=argparse.ArgumentParser();p.add_argument('library',type=Path);p.add_argument('--report',type=Path);a=p.parse_args();results=[]
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
   assert m.call(0x29b324)==0x3b96d4e8f2a5c719
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
 m=Android(a.library);m.run(b'wrong');s=m.run(b'@Icon_Crack');assert s['required']==0 and s['error']=='' and s['busy']==0;s['case']='invalid-then-valid';results.append(s)
 report={'library_sha256':hashlib.sha256(a.library.read_bytes()).hexdigest(),'cases_passed':len(results),'cases':results,'phone_tested':False}
 if a.report:a.report.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'cases_passed':len(results),'library_sha256':report['library_sha256']},indent=2))
if __name__=='__main__':main()
