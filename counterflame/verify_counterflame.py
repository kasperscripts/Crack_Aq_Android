from macho_image import *
from unicorn import UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC,UC_HOOK_CODE

def image(patched=True,cache=None,start=True):
 m=Image(d.root/'cf-menu-icon.dylib' if patched else None)
 if cache is not None:m.keychain=dict(cache)
 m.call(0x83c4)
 for name,prot in [('__TEXT',UC_PROT_READ|UC_PROT_EXEC),('__DATA_CONST',UC_PROT_READ),('__DATA',UC_PROT_READ|UC_PROT_WRITE),('__LINKEDIT',UC_PROT_READ)]:
  s=d.b.get_segment(name);m.u.mem_protect(BASE+s.virtual_address,(s.virtual_size+4095)&~4095,prot)
 if start:m.call(0x4a28)
 return m
def activate(m,key):
 p=m.malloc(len(key.encode())+1);m.u.mem_write(p,key.encode()+b'\0');m.call(0x57e4,p)
def state(m):
 return {'authenticated':bool(m.call(0x55a0)),'status':int.from_bytes(m.u.mem_read(BASE+0x1330b0,4),'little'),'plan':m.string(BASE+0x1330b8).decode(),'message':m.string(BASE+0x133100).decode(),'expires_at':int.from_bytes(m.u.mem_read(BASE+0x133118,8),'little'),'checking':bool(m.u.mem_read(BASE+0x133120,1)[0])}
def reply(m,value,status=200):
 b=m.network[-1][1];invoke=int.from_bytes(m.u.mem_read(b+16,8),'little')-BASE;m.call(invoke,b,m.obj(json.dumps(value).encode()),m.obj({'_type':'response','status':status}),0)

if __name__=='__main__':
 profile=json.loads((d.root/'patch-map.json').read_text())['profile']
 baseline=image(False);activate(baseline,'@Icon_Crack');assert len(baseline.network)==1;reply(baseline,profile)
 local=image();activate(local,'@Icon_Crack');assert not local.network;assert state(local)==state(baseline);assert local.keychain==baseline.keychain
 assert state(local)['authenticated'] and state(local)['plan']=='Premium' and state(local)['message']=='License activated'
 cached=image(cache=local.keychain);assert not cached.network and state(cached)['authenticated'] and state(cached)['plan']=='Premium'
 key_buffer=cached.malloc(128);cached.call(0x7658,key_buffer,128);assert cached.cstr(key_buffer)==b'@Icon_Crack'
 trimmed=image();activate(trimmed,'  @Icon_Crack \n');assert state(trimmed)['authenticated']
 empty=image();activate(empty,'');assert not state(empty)['authenticated'] and not empty.network
 wrong=image();activate(wrong,'definitely-wrong-key');assert not state(wrong)['authenticated'] and len(wrong.network)==1 and wrong.jsons[0]['key']=='definitely-wrong-key';reply(wrong,{'message':'Invalid license'},403);assert not state(wrong)['authenticated']
 cached.call(0x7458);baseline.call(0x7458);assert not state(cached)['authenticated'];assert state(cached)==state(baseline) and cached.keychain==baseline.keychain
 brands=['CS MOBILE  |  By @hgbao209','CS MOBILE  By @hgbao209','Made by @hgbao209']
 for label in brands+['Settings']:
  a=image();src=a.malloc(24);out=a.malloc(24);a.putstr(src,label);a.u.reg_write(UC_ARM64_REG_X8,out);a.call(0x319e0,src);value=a.string(out).decode()
  if label in brands:assert value=='@Icon_Crack бай бай жирный'
  else:assert value==label
 for pressed in [False,True]:
  a=image();buttons=[]
  def button(u,pc,size,data):buttons.append(a.cstr(a.reg(0)).decode());a.ret(int(pressed))
  hook=a.u.hook_add(UC_HOOK_CODE,button,begin=BASE+0x92404,end=BASE+0x92404);text=a.malloc(128);a.u.mem_write(text,'@Icon_Crack бай бай жирный'.encode()+b'\0');a.call(0x127840,0,text);a.u.hook_del(hook)
  assert buttons==['@Icon_Crack бай бай жирный'] and len(a.queued)==int(pressed)
  if pressed:
   b=a.queued[0][1];a.call(0x127940,b);assert a.opened_urls==['https://t.me/Icon_Crack']
 report={'key':'@Icon_Crack','display':'@Icon_Crack бай бай жирный','data_const_read_only_text_rx_data_rw_enforced':True,'original_activation_callback_state_reproduced':True,'state':state(local),'keychain_cache_matches_original_callback':True,'cached_launch_local_validation_verified':True,'empty_and_incorrect_keys_rejected':True,'whitespace_trimming_preserved':True,'logout_verified':True,'three_branding_variants_replaced':True,'unrelated_ui_text_preserved':True,'telegram_target':'https://t.me/Icon_Crack','telegram_opens_only_on_click_via_main_queue':True,'supplied_server_license_embedded':False,'physical_ios_device_tested':False}
 (d.root/'native-verification.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS: original callback, fixed key, cached login, wrong/empty keys, logout, branding and Telegram with protected memory')
