"""Read and CRC-check every archive entry through the independent minizip reader."""
import argparse,ctypes,ctypes.util,hashlib,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('ipa',type=Path);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
report=json.loads(a.report.read_text());expected={e['name']:e for e in report['entries']}
library=ctypes.util.find_library('minizip');assert library,'minizip library required'
lib=ctypes.CDLL(library);handle=ctypes.c_void_p
lib.unzOpen64.argtypes=[ctypes.c_char_p];lib.unzOpen64.restype=handle
for name in ['unzGoToFirstFile','unzGoToNextFile','unzOpenCurrentFile','unzCloseCurrentFile','unzClose']:
    fn=getattr(lib,name);fn.argtypes=[handle];fn.restype=ctypes.c_int
lib.unzGetCurrentFileInfo64.argtypes=[handle,ctypes.c_void_p,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_void_p,ctypes.c_ulong,ctypes.c_void_p,ctypes.c_ulong];lib.unzGetCurrentFileInfo64.restype=ctypes.c_int
lib.unzReadCurrentFile.argtypes=[handle,ctypes.c_void_p,ctypes.c_uint];lib.unzReadCurrentFile.restype=ctypes.c_int
archive=lib.unzOpen64(str(a.ipa).encode());assert archive
count=0;buffer=ctypes.create_string_buffer(4*1024*1024);filename=ctypes.create_string_buffer(4096)
try:
    status=lib.unzGoToFirstFile(archive)
    while status==0:
        assert lib.unzGetCurrentFileInfo64(archive,None,filename,len(filename),None,0,None,0)==0
        name=filename.value.decode('utf-8');entry=expected.pop(name);digest=hashlib.sha256();size=0
        assert lib.unzOpenCurrentFile(archive)==0,name
        while True:
            n=lib.unzReadCurrentFile(archive,buffer,len(buffer));assert n>=0,(name,n)
            if n==0:break
            digest.update(memoryview(buffer).cast('B')[:n]);size+=n
        assert lib.unzCloseCurrentFile(archive)==0,name
        assert size==entry['size'] and digest.hexdigest()==entry['sha256'],name
        count+=1;status=lib.unzGoToNextFile(archive)
    assert status==-100 and not expected
finally:assert lib.unzClose(archive)==0
report['independent_minizip_full_extraction_crc_sha256_verified']=True
a.report.write_text(json.dumps(report,indent=2)+'\n')
print('PASS: minizip independently extracted all',count,'entries; CRC, sizes and SHA-256 match',flush=True)
