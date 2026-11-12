#!/usr/bin/env python3
"""Exercise renderer startup with an absent and a populated game table."""
import argparse,json,struct
from pathlib import Path
from unicorn import UcError
from unicorn.arm64_const import UC_ARM64_REG_X8,UC_ARM64_REG_X9,UC_ARM64_REG_X19
from native_image import Image,BASE,HOST
p=argparse.ArgumentParser();p.add_argument('library',type=Path);p.add_argument('--previous-library',type=Path);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
results=[]
def renderer(m,value):
 table=HOST+0x180000
 m.u.mem_write(BASE+0x5c7598,struct.pack('<Q',table if value is not None else 0))
 if value is not None:m.u.mem_write(table,struct.pack('<Q',value))
 m.u.emu_start(BASE+0x1d236c,BASE+0x1d2388,count=100)
 return m.u.reg_read(UC_ARM64_REG_X8),m.u.reg_read(UC_ARM64_REG_X9)
if a.previous_library:
 old=Image(a.previous_library);old.init()
 try:renderer(old,None)
 except UcError:results.append({'case':'previous-null-game-table','invalid_read_reproduced':True})
 else:raise AssertionError('previous library did not reproduce the missing-table access')
for value in [None,0,HOST+0x190000]:
 m=Image(a.library);m.init();x8,x9=renderer(m,value)
 assert x8==(value or 0) and x9==0x8a1e5d5c465df37e
 results.append({'case':'renderer-missing-table' if value is None else 'renderer-empty-camera' if value==0 else 'renderer-initialized-table','passed':True})
m=Image(a.library);m.init();out=HOST+0x1b0000;table=HOST+0x180000
for ptr,fn,ready,camera,expected in [(0,0,0,0,b'Game module loading'),(table,0,0,0,b'Game module loading'),(table,HOST+0x190000,0,0,b'Waiting for game world'),(table,HOST+0x190000,1,0,b'Waiting for game world'),(table,HOST+0x190000,1,HOST+0x1c0000,b'Game world ready')]:
 m.u.mem_write(BASE+0x5c7598,struct.pack('<Q',ptr));m.u.mem_write(table,struct.pack('<Q',fn));m.u.mem_write(BASE+0x5c7764,bytes([ready]));m.u.mem_write(BASE+0x5c7768,struct.pack('<Q',camera));m.u.reg_write(UC_ARM64_REG_X8,out);m.u.reg_write(UC_ARM64_REG_X19,0x123456789abcdef0)
 m.call(0x29c058);assert m.string(out)==expected;assert m.u.reg_read(UC_ARM64_REG_X19)==0x123456789abcdef0
 results.append({'case':'startup-footer','value':expected.decode(),'passed':True})
report={'cases_passed':len(results),'cases':results,'physical_phone_tested':False,'actual_game_callbacks_tested':False,'scope':'Native renderer null-table block and existing footer return ABI'}
a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'cases_passed':len(results)}))
