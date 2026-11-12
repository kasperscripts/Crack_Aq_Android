import json,struct,sys,re,secrets,hashlib,random,base64,urllib.parse
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
from keystone import Ks,KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN
import inspect_macho as d
BASE=0x100000000;HOST=BASE+0x1000000;STACK=HOST+0x800000;STOP=HOST+0x100000
class Image:
 def __init__(self):
  self.u=u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM64_MAX);u.mem_map(BASE,0x500000);u.mem_map(HOST,0x4000000);self.rng=random.Random(69);self.alloc=HOST+0x1000000;self.names={};self.objects={};self.buffers={};self.messages=[];self.jsons=[];self.network=[];self.public_keys=[];self.seen_strings=set();self.dynamic={};self.imp_blocks={};self.queued=[];self.selectors={};self.classes={};self.reg_methods={}
  for s in d.b.segments:
   if s.file_size:u.mem_write(BASE+s.virtual_address,bytes(s.content))
  for r in d.b.relocations:
   a=BASE+r.address;v=int.from_bytes(u.mem_read(a,8),'little');u.mem_write(a,struct.pack('<Q',(v+BASE)&((1<<64)-1)))
  for binding in d.b.dyld_info.bindings:
   name=binding.symbol.name
   if name not in self.names.values():
    a=HOST+len(self.names)*16;self.names[a]=name;u.mem_write(a,bytes.fromhex('c0035fd6'))
   else:a=next(k for k,v in self.names.items() if v==name)
   u.mem_write(BASE+binding.address,struct.pack('<Q',a))
   if name.startswith('_OBJC_CLASS_$_'):self.objects[a]=('class',name.split('$_')[1])
  for s in d.b.symbols:
   if s.name.startswith('_OBJC_CLASS_$_') and s.value:
    name=s.name.split('$_')[1];self.classes[name]=BASE+s.value;self.objects[BASE+s.value]=('class',name)
  classlist=d.b.get_section('__objc_classlist')
  for i in range(classlist.size//8):
   cls=d.q(classlist.virtual_address+i*8);name=d.cstr(d.q((d.q(cls+32)&~7)+24));self.classes[name]=BASE+cls;self.objects[BASE+cls]=('class',name)
  for pc,label in d.methods.items():
   match=re.match(r'([+-])\[(\S+) (.*)\]',label)
   if match:self.reg_methods[(match[2],match[3],match[1]=='+')]=pc
  self.cfstrings={BASE+int(x['address'],16):x['value'] for x in json.loads((d.root/'cfstrings.json').read_text())}
  for address,name in self.names.items():
   if name.startswith('_kSec') or name.startswith('_kCF'):
    value=True if name=='_kCFBooleanTrue' else False if name=='_kCFBooleanFalse' else name
    u.mem_write(address,struct.pack('<Q',self.obj(value)))
  self.u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20)
  u.hook_add(UC_HOOK_CODE,self.external,begin=HOST,end=HOST+0xffff)
  code=bytes(Ks(KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN).asm('stp x29,x30,[sp,#-16]!; mov x0,x1; ldr x8,[x1,#16]; blr x8; ldp x29,x30,[sp],#16; ret')[0]);u.mem_write(HOST+0x20000,code)
 def reg(self,n):return self.u.reg_read(UC_ARM64_REG_X0+n)
 def ret(self,v=0):self.u.reg_write(UC_ARM64_REG_X0,v);self.u.reg_write(UC_ARM64_REG_PC,self.u.reg_read(UC_ARM64_REG_LR))
 def malloc(self,n):
  p=self.alloc;self.alloc+=(n+31)&~15;assert self.alloc<HOST+0x3f00000;return p
 def cstr(self,p):return bytes(self.u.mem_read(p,16384)).split(b'\0')[0]
 def obj(self,v):
  p=self.malloc(128);self.objects[p]=v
  if isinstance(v,str):self.seen_strings.add(v)
  return p
 def value(self,p):
  if p==0:return None
  if p in self.buffers:
   q,n=self.buffers[p];return bytes(self.u.mem_read(q,n))
  if p in self.objects:return self.objects[p]
  if p in self.cfstrings:return self.cfstrings[p]
  raise RuntimeError(('unknown object',hex(p),hex(p-BASE)))
 def string(self,p):
  h=bytes(self.u.mem_read(p,24))
  if h[23]&0x80:address,n,_=struct.unpack('<3Q',h);return bytes(self.u.mem_read(address,n))
  return h[:h[23]]
 def putstr(self,p,s):
  if isinstance(s,str):s=s.encode()
  if len(s)<=22:self.u.mem_write(p,s+bytes(23-len(s))+bytes([len(s)]))
  else:
   q=self.malloc(len(s)+1);self.u.mem_write(q,s+b'\0');self.u.mem_write(p,struct.pack('<3Q',q,len(s),((len(s)+16)&~15)|(1<<63)))
 def external(self,u,pc,size,data):
  name=self.names[pc];a=[self.reg(i) for i in range(7)]
  if name in ['_objc_retain','_objc_retainAutorelease','_objc_autorelease','_objc_autoreleaseReturnValue','_objc_retainAutoreleasedReturnValue','_objc_retainAutoreleaseReturnValue','_objc_unsafeClaimAutoreleasedReturnValue']:self.ret(a[0])
  elif name in ['_objc_release','_objc_autoreleasePoolPop','___cxa_atexit','_free','__ZdlPv','__ZdlPvm']:self.ret()
  elif name in ['_objc_alloc_init','_objc_alloc']:
   kind=self.value(a[0])[1];v=[] if kind.endswith('Array') else {} if kind.endswith('Dictionary') else '' if kind.endswith('String') else b'' if kind.endswith('Data') else ('instance',kind);self.ret(self.obj(v))
  elif name=='_objc_storeStrong':u.mem_write(a[0],struct.pack('<Q',a[1]));self.ret()
  elif name=='_objc_autoreleasePoolPush':self.ret(HOST+0x110000)
  elif name in ['_malloc','__Znwm','__Znam']:self.ret(self.malloc(a[0]))
  elif name in ['_strlen','___strlen_chk']:self.ret(len(self.cstr(a[0])))
  elif name in ['_memcpy','_memmove','___memcpy_chk']:u.mem_write(a[0],bytes(u.mem_read(a[1],a[2])));self.ret(a[0])
  elif name=='_strncpy':
   value=self.cstr(a[1]);value=value[:a[2]]+bytes(max(0,a[2]-len(value)));u.mem_write(a[0],value);self.ret(a[0])
  elif name=='_bzero':u.mem_write(a[0],bytes(a[1]));self.ret()
  elif name in ['_memset','___memset_chk']:u.mem_write(a[0],bytes([a[1]&255])*a[2]);self.ret(a[0])
  elif name in ['_memcmp','_strcmp']:
   x,y=(bytes(u.mem_read(a[0],a[2])),bytes(u.mem_read(a[1],a[2]))) if name=='_memcmp' else (self.cstr(a[0]),self.cstr(a[1]));self.ret((x>y)-(x<y))
  elif 'basic_string' in name:
   if name.endswith('6__initEPKcm'):self.putstr(a[0],bytes(u.mem_read(a[1],a[2])));self.ret(a[0])
   elif name.endswith('C1ERKS5_') or name.endswith('aSERKS5_'):self.putstr(a[0],self.string(a[1]));self.ret(a[0])
   elif name.endswith('6assignEPKc'):self.putstr(a[0],self.cstr(a[1]));self.ret(a[0])
   elif name.endswith('D1Ev') or name.endswith('D2Ev'):self.ret()
   else:raise RuntimeError(('string import',name))
  elif name=='___cxa_guard_acquire':self.ret(0 if u.mem_read(a[0],1)[0] else 1)
  elif name=='___cxa_guard_release':u.mem_write(a[0],b'\1');self.ret()
  elif name in ['_pthread_mutex_lock','_pthread_mutex_unlock','_pthread_mutex_init']:self.ret()
  elif name=='__ZNSt3__112__next_primeEm':
   import math
   value=max(2,a[0])
   while any(value%n==0 for n in range(2,math.isqrt(value)+1)):value+=1
   self.ret(value)
  elif name in ['_CC_SHA256','_CC_MD5']:
   h=hashlib.sha256 if name=='_CC_SHA256' else hashlib.md5;u.mem_write(a[2],h(bytes(u.mem_read(a[0],a[1]))).digest());self.ret(a[2])
  elif name=='_SecKeyCreateWithData':
   from cryptography.hazmat.primitives.serialization import load_der_public_key
   self.public_keys.append(self.value(a[0]));key=load_der_public_key(self.value(a[0]));self.ret(self.obj(('rsa',key)))
  elif name=='_SecKeyCreateEncryptedData':
   from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
   key=self.value(a[0])[1];self.ret(self.obj(key.encrypt(self.value(a[2]),PKCS1v15())))
  elif name=='_SecKeyVerifySignature':
   from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
   from cryptography.hazmat.primitives.hashes import SHA256
   self.value(a[0])[1].verify(self.value(a[3]),self.value(a[2]),PKCS1v15(),SHA256());self.signature_verified=True;self.ret(1)
  elif name=='_CCCrypt':
   from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
   from cryptography.hazmat.primitives.padding import PKCS7
   sp=u.reg_read(UC_ARM64_REG_SP);out,available,moved=struct.unpack('<3Q',u.mem_read(sp,24));key=bytes(u.mem_read(a[3],a[4]));data=bytes(u.mem_read(a[6],self.reg(7)));mode=modes.ECB() if a[2]&2 else modes.CBC(bytes(u.mem_read(a[5],16)));self.last_aes={'key':key,'iv':bytes(u.mem_read(a[5],16)),'in':data,'operation':a[0]}
   if a[0]==0:
    if a[2]&1:pad=PKCS7(128).padder();data=pad.update(data)+pad.finalize()
    c=Cipher(algorithms.AES(key),mode).encryptor();value=c.update(data)+c.finalize()
   else:
    c=Cipher(algorithms.AES(key),mode).decryptor();value=c.update(data)+c.finalize()
    if a[2]&1:pad=PKCS7(128).unpadder();value=pad.update(value)+pad.finalize()
   assert len(value)<=available;u.mem_write(out,value);u.mem_write(moved,struct.pack('<Q',len(value)));self.ret()
  elif name=='_SecItemCopyMatching':
   if a[1]:u.mem_write(a[1],bytes(8))
   self.ret((1<<32)-25300)
  elif name in ['_SecItemAdd','_SecItemUpdate','_SecItemDelete','_CFRelease']:self.ret()
  elif name=='_SecRandomCopyBytes':
   value=self.entropy_samples.pop(0) if getattr(self,'entropy_samples',[]) else secrets.token_bytes(a[1]);assert len(value)==a[1];u.mem_write(a[2],value);self.ret()
  elif name=='_arc4random_uniform':self.ret(self.rng.randrange(a[0]) if a[0] else 0)
  elif name=='_dispatch_once':
   if int.from_bytes(u.mem_read(a[0],8),'little')==(1<<64)-1:self.ret()
   else:u.mem_write(a[0],b'\xff'*8);u.reg_write(UC_ARM64_REG_PC,HOST+0x20000)
  elif name=='_objc_retainBlock':
   descriptor=int.from_bytes(u.mem_read(a[0]+24,8),'little');n=int.from_bytes(u.mem_read(descriptor+8,8),'little');assert 32<=n<1024,n;p=self.malloc(n);u.mem_write(p,bytes(u.mem_read(a[0],n)));self.ret(p)
  elif name=='_imp_implementationWithBlock':
   p=self.malloc(64);block=a[0];asm='mov x1,x0; movz x0,#'+str(block&65535)
   for i in range(1,4):asm+='; movk x0,#'+str((block>>(16*i))&65535)+',lsl #'+str(16*i)
   asm+='; ldr x8,[x0,#16]; br x8';u.mem_write(p,bytes(Ks(KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN).asm(asm,p)[0]));self.imp_blocks[p]=block;self.ret(p)
  elif name=='_class_addMethod':self.dynamic[(a[0],self.cstr(a[1]).decode())]=self.imp_blocks[a[2]];self.ret(1)
  elif name=='_objc_getClass':
   label=self.cstr(a[0]).decode();existing=next((p for p,v in self.objects.items() if v==('class',label)),None);self.ret(existing or self.obj(('class',label)))
  elif name=='_NSSearchPathForDirectoriesInDomains':self.ret(self.obj([self.obj('/fixture/Documents')]))
  elif name=='_NSSelectorFromString':
   value=self.value(a[0])
   if value not in self.selectors:
    p=self.malloc(len(value)+1);u.mem_write(p,value.encode()+b'\0');self.selectors[value]=p
   self.ret(self.selectors[value])
  elif name=='_objc_msgSend':self.message(a)
  elif name in ['_dispatch_async','_dispatch_after']:
   block=a[1] if name=='_dispatch_async' else a[2];descriptor=int.from_bytes(u.mem_read(block+24,8),'little');n=int.from_bytes(u.mem_read(descriptor+8,8),'little');assert 32<=n<=4096;nptr=self.malloc(n);u.mem_write(nptr,bytes(u.mem_read(block,n)));self.queued.append((name,nptr));self.ret()
  elif name.startswith('_dispatch_'):raise RuntimeError(('unsupported dispatch',name))
  else:raise RuntimeError(('import',name,[hex(x) for x in a[:4]]))
 def format_string(self,fmt,sp):
  i=0
  def replace(m):
   nonlocal i
   token=m[0]
   if token=='%%':return '%'
   raw=bytes(self.u.mem_read(sp+i*8,8));i+=1;value=int.from_bytes(raw,'little');kind=token[-1]
   if kind=='@':return str(self.value(value))
   if kind in ['C','c']:return chr(value)
   if kind=='s':return self.cstr(value).decode()
   if kind=='p':return hex(value)
   clean=re.sub(r'(ll|l|z)(?=[diuoxX])','',token)
   if kind in ['f','F','e','E','g','G']:value=struct.unpack('<d',raw)[0]
   return clean%value
  return re.sub(r'%%|%[-+ #0-9.]*(?:ll|l|z)?[@diuoxXfFeEgGscCp]',replace,fmt)
 def objc_tree(self,v):
  if isinstance(v,dict):return self.obj({k:self.objc_tree(x) for k,x in v.items()})
  if isinstance(v,list):return self.obj([self.objc_tree(x) for x in v])
  return self.obj(v) if v is not None else 0
 def json_value(self,p):
  v=self.value(p)
  if isinstance(v,dict):return {k:self.json_value(x) for k,x in v.items()}
  if isinstance(v,list):return [self.json_value(x) for x in v]
  return v
 def message(self,a):
  u=self.u;receiver=a[0];sel=self.cstr(a[1]).decode();v=self.value(receiver);self.messages.append((v if isinstance(v,tuple) else type(v).__name__,sel))
  if receiver==0:self.ret();return
  if isinstance(v,tuple) and v[0]=='instance' and (v[1],sel,False) in self.reg_methods:u.reg_write(UC_ARM64_REG_PC,BASE+self.reg_methods[(v[1],sel,False)]);return
  if isinstance(v,tuple) and v[0]=='class' and (v[1],sel,True) in self.reg_methods:u.reg_write(UC_ARM64_REG_PC,BASE+self.reg_methods[(v[1],sel,True)]);return
  if sel=='writeLog:':self.ret()
  elif sel in ['performSelector:withObject:','performSelector:']:
   label=self.cstr(a[2]).decode();cls=self.classes[v[1]];block=self.dynamic[(cls,label)]
   u.reg_write(UC_ARM64_REG_X0,block);u.reg_write(UC_ARM64_REG_X1,receiver);u.reg_write(UC_ARM64_REG_X2,a[3] if sel.endswith('withObject:') else 0);u.reg_write(UC_ARM64_REG_PC,int.from_bytes(u.mem_read(block+16,8),'little'))
  elif sel in ['respondsToSelector:','methodForSelector:']:
   label=self.cstr(a[2]).decode();cls=self.classes[v[1]] if isinstance(v,tuple) and v[0]=='instance' else receiver;block=self.dynamic.get((cls,label));method=self.reg_methods.get((v[1],label,v[0]=='class')) if isinstance(v,tuple) else None
   if sel=='respondsToSelector:':self.ret(int(bool(block or method)))
   elif block:self.ret(next(p for p,b in self.imp_blocks.items() if b==block))
   elif method:self.ret(BASE+method)
   else:self.ret()
  elif sel=='class':self.ret(self.classes[v[1]] if isinstance(v,tuple) and v[0]=='instance' else receiver)
  elif sel=='alloc':self.ret(self.obj(('instance',v[1])))
  elif sel=='scannerWithString:':self.ret(self.obj(('scanner',self.value(a[2]))))
  elif sel=='scanHexLongLong:':u.mem_write(a[2],struct.pack('<Q',int(v[1],16)));self.ret(1)
  elif sel=='setScanLocation:':self.ret()
  elif sel=='URLWithString:':self.ret(self.obj(('url',self.value(a[2]))))
  elif sel=='sharedApplication':self.ret(self.obj(('instance','UIApplication')))
  elif sel in ['setDateFormat:','setLocale:','setTimeZone:']:self.ret()
  elif sel=='timeZoneWithAbbreviation:':self.ret(self.obj(('timezone',self.value(a[2]))))
  elif sel=='localTimeZone':self.ret(self.obj(('timezone','UTC')))
  elif sel=='date':self.ret(self.obj(('date',1750000000.0)))
  elif sel=='timeIntervalSinceDate:':
   value=v[1]-self.value(a[2])[1];u.reg_write(UC_ARM64_REG_D0,struct.unpack('<Q',struct.pack('<d',value))[0]);self.ret()
  elif sel=='stringFromDate:':
   import datetime
   self.ret(self.obj(datetime.datetime.fromtimestamp(self.value(a[2])[1],datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')))
  elif sel=='setDouble:forKey:':
   value=struct.unpack('<d',struct.pack('<Q',u.reg_read(UC_ARM64_REG_D0)))[0];v[self.value(a[2])]=self.obj(value);self.ret()
  elif sel=='dateFromString:':
   import datetime
   date=datetime.datetime.strptime(self.value(a[2]),'%Y-%m-%d %H:%M:%S').replace(tzinfo=datetime.timezone.utc);self.ret(self.obj(('date',date.timestamp())))
  elif sel=='timeIntervalSince1970':
   u.reg_write(UC_ARM64_REG_D0,struct.unpack('<Q',struct.pack('<d',v[1]))[0]);self.ret()
  elif sel=='openURL:options:completionHandler:':
   assert v==('instance','UIApplication');assert self.value(a[3])=={};assert a[4]==0
   self.opened_urls=getattr(self,'opened_urls',[])+[self.value(a[2])[1]];self.ret()
  elif sel in ['host','scheme','absoluteString']:
   value=v[1] if sel=='absoluteString' else urllib.parse.urlsplit(v[1]).hostname if sel=='host' else urllib.parse.urlsplit(v[1]).scheme;self.ret(self.obj(value))
  elif sel=='stringByAppendingString:':self.ret(self.obj(v+self.value(a[2])))
  elif sel=='stringByAppendingPathComponent:':self.ret(self.obj(v.rstrip('/')+'/'+self.value(a[2])))
  elif sel=='firstObject':self.ret(v[0] if v else 0)
  elif sel=='objectAtIndex:':self.ret(v[a[2]])
  elif sel=='defaultManager':self.ret(self.obj(('instance','NSFileManager')))
  elif sel=='fileHandleForWritingAtPath:':self.ret(self.obj(('instance','NSFileHandle')))
  elif sel in ['seekToEndOfFile','writeData:','closeFile']:self.ret()
  elif sel in ['fileExistsAtPath:','fileExistsAtPath:isDirectory:']:self.ret(0)
  elif sel.startswith('createDirectoryAtPath:') or sel.startswith('writeToFile:'):self.ret(1)
  elif sel=='stringByReplacingOccurrencesOfString:withString:':self.ret(self.obj(v.replace(self.value(a[2]),self.value(a[3]))))
  elif sel=='substringFromIndex:':self.ret(self.obj(v[a[2]:]))
  elif sel=='substringToIndex:':self.ret(self.obj(v[:a[2]]))
  elif sel=='subdataWithRange:':self.ret(self.obj(v[a[2]:a[2]+a[3]]))
  elif sel=='substringWithRange:':self.ret(self.obj(v[a[2]:a[2]+a[3]]))
  elif sel=='componentsSeparatedByString:':self.ret(self.obj([self.obj(x) for x in v.split(self.value(a[2]))]))
  elif sel=='componentsJoinedByString:':self.ret(self.obj(self.value(a[2]).join(self.value(x) for x in v)))
  elif sel=='containsString:':self.ret(int(self.value(a[2]) in v))
  elif sel=='hasPrefix:':self.ret(int(v.startswith(self.value(a[2]))))
  elif sel=='lowercaseString':self.ret(self.obj(v.lower()))
  elif sel=='isEqualToString:':self.ret(int(v==self.value(a[2])))
  elif sel=='hasSuffix:':self.ret(int(v.endswith(self.value(a[2]))))
  elif sel in ['setHTTPMethod:','setHTTPBody:']:v[sel[3:-1]]=a[2];self.ret()
  elif sel=='setValue:forHTTPHeaderField:':v.setdefault('headers',{})[self.value(a[3])]=self.value(a[2]);self.ret()
  elif sel=='setTimeoutInterval:':self.ret()
  elif sel=='dataWithJSONObject:options:error:':
   value=self.json_value(a[2]);self.last_json=value;self.jsons.append(value)
   if a[4]:u.mem_write(a[4],bytes(8))
   self.ret(self.obj(json.dumps(value,separators=(',',':')).encode()))
  elif sel=='JSONObjectWithData:options:error:':
   if a[4]:u.mem_write(a[4],bytes(8))
   self.ret(self.objc_tree(json.loads(self.value(a[2]))))
  elif sel=='statusCode':self.ret(v['status'])
  elif sel=='isKindOfClass:':
   cls=self.value(a[2])[1];match=(cls in ['NSDictionary','NSMutableDictionary'] and isinstance(v,dict)) or (cls in ['NSArray','NSMutableArray'] and isinstance(v,list)) or (cls in ['NSString','NSMutableString'] and isinstance(v,str)) or (cls=='NSNumber' and isinstance(v,(int,float,bool))) or (cls in ['NSData','NSMutableData'] and isinstance(v,bytes)) or (cls=='NSHTTPURLResponse' and isinstance(v,dict) and v.get('_type')=='response');self.ret(int(match))
  elif sel in ['boolValue','intValue','integerValue','unsignedLongLongValue','longLongValue']:self.ret(int(v))
  elif sel=='defaultSessionConfiguration':self.ret(self.obj({'_type':'configuration'}))
  elif sel=='sessionWithConfiguration:delegate:delegateQueue:':self.ret(self.obj({'_type':'session','delegate':a[3]}))
  elif sel in ['setURLCache:','setRequestCachePolicy:','setHTTPShouldSetCookies:']:self.ret()
  elif sel=='dataTaskWithRequest:completionHandler:':
   block=a[3];descriptor=int.from_bytes(u.mem_read(block+24,8),'little');n=int.from_bytes(u.mem_read(descriptor+8,8),'little');p=self.malloc(n);u.mem_write(p,bytes(u.mem_read(block,n)));self.network.append((a[2],p));self.ret(self.obj({'_type':'task'}))
  elif sel in ['resume','finishTasksAndInvalidate']:self.ret()
  elif sel=='requestWithURL:':self.ret(self.obj({'_type':'request','url':self.value(a[2])[1]}))
  elif sel=='standardUserDefaults':
   if not hasattr(self,'defaults'):self.defaults=self.obj({})
   self.ret(self.defaults)
  elif sel in ['arrayForKey:','stringForKey:']:self.ret(v.get(self.value(a[2]),0))
  elif sel in ['boolForKey:','integerForKey:']:self.ret(self.value(v.get(self.value(a[2]),0)) or 0)
  elif sel in ['containsObject:']:self.ret(int(any(self.value(p)==self.value(a[2]) for p in v)))
  elif sel in ['addObject:']:v.append(a[2]);self.ret()
  elif sel in ['synchronize']:self.ret(1)
  elif sel in ['dictionary','array']:self.ret(self.obj({} if sel=='dictionary' else []))
  elif sel.startswith('numberWith'):self.ret(self.obj(a[2]))
  elif sel in ['setObject:forKey:','setObject:forKeyedSubscript:']:v[self.value(a[3])]=a[2];self.ret()
  elif sel in ['objectForKey:','objectForKeyedSubscript:']:self.ret(v.get(self.value(a[2]),0))
  elif sel=='dictionaryWithObjects:forKeys:count:':
   values=struct.unpack('<'+'Q'*a[4],u.mem_read(a[2],a[4]*8));keys=struct.unpack('<'+'Q'*a[4],u.mem_read(a[3],a[4]*8));self.ret(self.obj({self.value(k):v for k,v in zip(keys,values)}))
  elif sel=='count':self.ret(len(v))
  elif sel=='new':self.ret(self.obj(('instance',v[1])))
  elif sel in ['copy','mutableCopy']:self.ret(self.obj(v.copy()) if isinstance(v,(dict,list)) else receiver)
  elif sel=='init':self.ret(receiver)
  elif sel=='dataWithLength:':
   p=self.obj(bytes(a[2]));q=self.malloc(a[2]);u.mem_write(q,bytes(a[2]));self.buffers[p]=(q,a[2]);self.ret(p)
  elif sel in ['bytes','mutableBytes']:
   if receiver not in self.buffers:
    q=self.malloc(len(v));u.mem_write(q,v);self.buffers[receiver]=(q,len(v))
   self.ret(self.buffers[receiver][0])
  elif sel=='dataUsingEncoding:':self.ret(self.obj(v.encode()))
  elif sel in ['dataWithBytes:length:','initWithBytes:length:','dataWithBytesNoCopy:length:','dataWithBytesNoCopy:length:freeWhenDone:']:
   value=bytes(u.mem_read(a[2],a[3]));self.objects[receiver]=value if sel.startswith('init') else v;self.ret(receiver if sel.startswith('init') else self.obj(value))
  elif sel=='initWithData:':self.objects[receiver]=self.value(a[2]);self.ret(receiver)
  elif sel=='initWithBytes:length:encoding:':self.objects[receiver]=bytes(u.mem_read(a[2],a[3])).decode('utf-8');self.ret(receiver)
  elif sel=='initWithBase64EncodedString:options:':self.objects[receiver]=base64.b64decode(self.value(a[2]));self.ret(receiver)
  elif sel=='base64EncodedStringWithOptions:':self.ret(self.obj(base64.b64encode(v).decode()))
  elif sel=='stringWithCapacity:':self.ret(self.obj(''))
  elif sel=='stringWithUTF8String:':self.ret(self.obj(self.cstr(a[2]).decode()))
  elif sel=='stringWithCString:encoding:':self.ret(self.obj(self.cstr(a[2]).decode()))
  elif sel=='stringWithString:':self.ret(self.obj(self.value(a[2])))
  elif sel=='stringWithFormat:':self.ret(self.obj(self.format_string(self.value(a[2]),u.reg_read(UC_ARM64_REG_SP))))
  elif sel=='length':self.ret(len(v))
  elif sel=='characterAtIndex:':self.ret(ord(v[a[2]]))
  elif sel=='appendFormat:':self.objects[receiver]=v+self.format_string(self.value(a[2]),u.reg_read(UC_ARM64_REG_SP));self.ret()
  elif sel=='appendString:':self.objects[receiver]=v+self.value(a[2]);self.ret()
  elif sel=='getCString:maxLength:encoding:':
   data=v.encode();assert len(data)+1<=a[3];u.mem_write(a[2],data+b'\0');self.ret(1)
  elif sel=='initWithData:encoding:':self.objects[receiver]=self.value(a[2]).decode();self.ret(receiver)
  elif sel=='UTF8String':
   text=v.encode();p=self.malloc(len(text)+1);u.mem_write(p,text+b'\0');self.ret(p)
  else:raise RuntimeError(('message',v if isinstance(v,(str,tuple)) and len(str(v))<180 else type(v).__name__,sel,[hex(x) for x in a[2:5]]))
 def call(self,address,*args,count=5000000):
  u=self.u;u.reg_write(UC_ARM64_REG_SP,STACK);u.reg_write(UC_ARM64_REG_LR,STOP)
  for i,a in enumerate(args):u.reg_write(UC_ARM64_REG_X0+i,a)
  try:u.emu_start(BASE+address,STOP,count=count)
  except Exception as ex:raise RuntimeError(f'{hex(address)} PC={hex(u.reg_read(UC_ARM64_REG_PC)-BASE)}: {ex}') from ex
  assert u.reg_read(UC_ARM64_REG_PC)==STOP,('instruction limit',hex(u.reg_read(UC_ARM64_REG_PC)-BASE));return self.reg(0)
if __name__=='__main__':
 m=Image();m.call(0x18f4c8);print('C++ globals initialized')
 self=m.obj(('instance','ImGuiDrawView'));m.call(0x2ec7c,self,0);print('dynamic methods',[(m.cstr(sel).decode(),hex(int.from_bytes(m.u.mem_read(p+16,8),'little')-BASE)) for (cls,sel),p in m.dynamic.items()]);print('strings',sorted(m.seen_strings))
