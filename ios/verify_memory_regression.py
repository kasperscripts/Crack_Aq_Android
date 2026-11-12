from fixture_image import *
from unicorn import UC_HOOK_MEM_WRITE_PROT

previous=d.root/'YouAreRetardBro-v2.dylib'
cases=[]
for entry in [0x31268,0x3c76c]:
    m,v,_=initialized(True,native_path=previous);faults=[]
    def fault(u,access,address,size,value,data):
        faults.append(address-BASE);return False
    m.u.hook_add(UC_HOOK_MEM_WRITE_PROT,fault)
    b=next(b for b in m.dynamic.values() if int.from_bytes(m.u.mem_read(b+16,8),'little')==BASE+entry)
    try:m.call(entry,b,v,m.obj('@Icon_Crack'))
    except RuntimeError as e:assert 'WRITE_PROT' in str(e)
    else:raise AssertionError('Previous build must reproduce the protected-memory write')
    assert faults and all(0x3e8000<=a<0x3ec000 for a in faults)
    cases.append({'entry':hex(entry),'previous_protected_write_reproduced':True,'fault_addresses':[hex(a) for a in faults]})
section_end=max(s.virtual_address+s.size for s in d.b.sections if 0x3ec000<=s.virtual_address<0x494000)
assert section_end<=0x491b00 and 0x491bb0<0x494000
report={'previous_build_regression_cases':cases,'fixed_runtime_descriptors_in_writable_data_padding':True,'writable_data_sections_end':hex(section_end),'new_descriptor_addresses':['0x491b00','0x491b30','0x491b80'],'physical_ios_crash_log_available':False}
(d.root/'memory-regression-verification.json').write_text(json.dumps(report,indent=2)+'\n')
print('Reproduced both v2 read-only-memory faults; new descriptor region verified writable and outside all sections')
