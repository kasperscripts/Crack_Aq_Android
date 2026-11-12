from fixture_image import *
report={'key':'@Icon_Crack','paths':[],'ios_device_execution_tested':False}
expected=json.loads((d.root/'patch-map.json').read_text())['profile']['offsets']
for entry,handler in [(0x31268,0x383e8),(0x3c76c,0x453b8)]:
 m,v,_=initialized(True);b=next(b for b in m.dynamic.values() if int.from_bytes(m.u.mem_read(b+16,8),'little')==BASE+entry);m.call(entry,b,v,m.obj('@Icon_Crack'));assert not m.network and len(m.queued)==1
 block=m.queued[0][1];assert int.from_bytes(m.u.mem_read(block+16,8),'little')==BASE+handler
 assert m.value(int.from_bytes(m.u.mem_read(block+0x20,8),'little'))==m.value(int.from_bytes(m.u.mem_read(block+0x28,8),'little'))
 changed=success(m,block);values={}
 for name,value in expected.items():
  slots=[a for a in changed if a%8==0 and bytes(m.u.mem_read(BASE+a,8))==struct.pack('<Q',int(value,16))];assert slots,name;values[name]={'rva':value,'slots':[hex(a) for a in slots]}
 negative,v,_=initialized(True);b=next(b for b in negative.dynamic.values() if int.from_bytes(negative.u.mem_read(b+16,8),'little')==BASE+entry);negative.call(entry,b,v,negative.obj('definitely-wrong-key'));assert len(negative.network)==1 and not negative.queued and negative.jsons[0]['licenseKey']=='definitely-wrong-key'
 report['paths'].append({'entry':hex(entry),'original_success_handler':hex(handler),'fixed_key_accepted':True,'incorrect_key_sent_to_original_server_path':True,'ios_runtime_state':values})
(d.root/'fixed-key-verification.json').write_text(json.dumps(report,indent=2)+'\n');print('Both entry paths: fixed key, original success handlers, iOS addresses and incorrect key verified')
