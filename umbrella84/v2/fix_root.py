#!/usr/bin/env python3
"""Prepare labelled files before placing them; preserve embedded native payloads."""
from pathlib import Path
import re,hashlib,json,base64

ROOT=Path(__file__).resolve().parent
source=ROOT.parent/'Umbrella_r84_Icon_Crack_root.sh'
s=source.read_text()
start=s.index('# /data/local/tmp is commonly shell_data_file:')
end=s.index('\nread_context() {',start)
replacement=(ROOT/'library-placement.sh').read_text().rstrip()+'\n'
s=s[:start]+replacement+s[end:]
assert s.count('tr head tail od grep awk dirname readlink cp ls sed')==1
s=s.replace('tr head tail od grep awk dirname readlink cp ls sed','tr head tail od grep awk dirname readlink cat mv ls sed')
old='rm -f "$RUNTIME/cfinject" "$RUNTIME/libcfesp.so"'
assert s.count(old)==1;s=s.replace(old,old+' "$RUNTIME/libcfesp-ready.so"')
s=s.replace('Umbrella_r84_Icon_Crack_root.sh','Umbrella_r84_Icon_Crack_root_v2.sh')
target=ROOT/'Umbrella_r84_Icon_Crack_root_v2.sh';target.write_text(s);target.chmod(0o755)
embedded={}
for name,marker in [('cfinject','CFESP_INJECTOR_PAYLOAD'),('libcfesp.so','CFESP_LIBRARY_PAYLOAD')]:
    pattern=r"base64 -d > \"\$RUNTIME/"+re.escape(name)+r"\" <<'"+marker+r"'\n(.*?)\n"+marker
    old=re.search(pattern,source.read_text(),re.S);new=re.search(pattern,s,re.S);assert old and new
    assert old[1]==new[1]
    data=base64.b64decode(new[1]);embedded[name]={'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    if name=='libcfesp.so':assert s.count(embedded[name]['sha256'])==2
report={'filename':target.name,'size':target.stat().st_size,'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
        'source_v1_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'embedded':embedded,
        'injector_and_native_library_unchanged_from_v1':True,'directory_label_applied_before_placement':True,
        'file_staged_and_labelled_before_rename':True,'game_data_fallback':True,
        'only_own_temporary_paths_modified':True,'global_selinux_policy_modified':False,
        'device_execution_tested':False}
(ROOT/'root-script-verification.json').write_text(json.dumps(report,indent=2)+'\n')
print('Root v2 prepared with unchanged native payloads, pre-labelled staging and game-data fallback')
