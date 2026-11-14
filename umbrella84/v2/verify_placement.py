#!/usr/bin/env python3
"""Run real shell preparation/cleanup with modelled Android labels and denials."""
from pathlib import Path
import hashlib,json,os,re,shutil,subprocess,tempfile

ROOT=Path(__file__).resolve().parent
PACKAGE='com.catsbit.oxidesurvivalisland'

MODEL=r'''
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
label_file() { printf '%s' "$1" | sha256sum | awk -v dir="$TEST_META" '{ print dir "/" $1 }'; }
context_of() {
    metadata=$(label_file "$1")
    if [ -f "$metadata" ]; then command cat "$metadata"; return; fi
    case "$1" in
        "$TEST_ROOT"/data/app/*) printf '%s' 'u:object_r:apk_data_file:s0' ;;
        "$TEST_ROOT"/data/user/*) printf '%s' 'u:object_r:app_data_file:s0:c1,c2' ;;
        *) printf '%s' 'u:object_r:shell_data_file:s0' ;;
    esac
}
ls() {
    if [ "${1:-}" = -Zd ]; then printf '%s %s\n' "$(context_of "$2")" "$2";
    else command ls "$@"; fi
}
pm() { printf 'package:%s/data/app/package/base.apk\n' "$TEST_ROOT"; }
getenforce() { printf '%s\n' "$TEST_SELINUX"; }
cp() { printf 'cp-denied\n' >> "$TEST_EVENTS"; printf '%s\n' 'Permission denied' >&2; return 13; }
chcon() {
    context=$1;shift
    for path do
        case "$path" in
            "$RUNTIME/libcfesp-ready.so"|*/cfesp-launch.????????|*/cfesp-launch.????????/libcfesp.so) ;;
            *) fail "relabel outside new temporary paths: $path" ;;
        esac
        printf 'label|%s|%s\n' "$context" "$path" >> "$TEST_EVENTS"
        if [ "$TEST_FAIL_LABEL" = 1 ]; then return 1; fi
        printf '%s' "$context" > "$(label_file "$path")"
    done
}
mv() {
    src=$1;dst=$2
    printf 'move|%s|%s\n' "$src" "$dst" >> "$TEST_EVENTS"
    if [ "$TEST_SELINUX" != Disabled ]; then
        [ "$(context_of "$src")" = 'u:object_r:apk_data_file:s0' ] || fail 'source not pre-labelled'
        parent=$(dirname "$dst");ancestor=$(dirname "$parent")
        [ "$(context_of "$parent")" = "$(context_of "$ancestor")" ] || fail 'destination directory not pre-labelled'
    fi
    case "$dst" in
        "$TEST_ROOT"/data/app/*) if [ "$TEST_DENY_PRIMARY" = 1 ]; then return 13; fi ;;
    esac
    if [ "$TEST_DENY_ALL" = 1 ]; then return 13; fi
    current_context=$(context_of "$src")
    command mv "$src" "$dst" || return
    printf '%s' "$current_context" > "$(label_file "$dst")"
}
'''

def run(name,original=False,deny_primary=False,deny_all=False,disabled=False,fail_label=False,corrupt=False):
    directory=Path(tempfile.mkdtemp(prefix='placement-',dir=ROOT))
    native=directory/'data/app/package/lib/arm64';native.mkdir(parents=True)
    data=directory/'data/user/0'/PACKAGE;cache=data/'code_cache';cache.mkdir(parents=True)
    (native/'libunity.so').write_bytes(b'existing game library')
    (native.parents[1]/'base.apk').write_bytes(b'existing game APK')
    runtime=directory/'runtime';runtime.mkdir(mode=0o700)
    payload=bytearray((ROOT/'libcfesp-icon.so').read_bytes())
    if corrupt:payload[-1]^=1
    (runtime/'libcfesp.so').write_bytes(payload)
    (runtime/'cfinject').write_bytes(b'not executed')
    meta=directory/'labels';meta.mkdir();events=directory/'events';events.write_text('')
    path=ROOT.parent/'Umbrella_r84_Icon_Crack_root.sh' if original else ROOT/'Umbrella_r84_Icon_Crack_root_v2.sh'
    text=path.read_text()
    begin=text.index('# /data/local/tmp is commonly shell_data_file:') if original else text.index('# Called only for new private temporary directories')
    end=text.index('\nclock_seconds() {',begin)
    functions=text[begin:end]
    cleanup=re.search(r'(?m)^cleanup\(\) \{\n.*?^\}',text,re.S)[0]
    # Only substitute Android absolute roots in the harness, never on a device.
    functions=functions.replace('/data/',str(directory)+'/data/').replace('/mnt/expand/',str(directory)+'/mnt/expand/')
    harness=directory/'case.sh'
    harness.write_text('set -eu\numask 077\n'+MODEL+'\n'+functions+'\n'+cleanup+'''
PACKAGE=com.catsbit.oxidesurvivalisland
USER_ID=0
RUNTIME="$TEST_ROOT/runtime"
LIBRARY_DIR=''
LIBRARY=''
trap cleanup EXIT
prepare_library
printf 'READY:%s\n' "$LIBRARY"
ACTUAL=$(sha256sum "$LIBRARY")
[ "${ACTUAL%% *}" = 981ac3443956ec285d4d6292db0e6f63e88c3e722dbc869c341c9d596bc1bf7d ] || fail 'bad final payload'
printf 'READY_HASH_OK\n'
''')
    env=os.environ.copy();env.update(TEST_ROOT=str(directory),TEST_META=str(meta),TEST_EVENTS=str(events),
        TEST_DENY_PRIMARY=str(int(deny_primary)),TEST_DENY_ALL=str(int(deny_all)),
        TEST_SELINUX='Disabled' if disabled else 'Enforcing',TEST_FAIL_LABEL=str(int(fail_label)))
    result=subprocess.run(['sh',str(harness)],env=env,text=True,capture_output=True)
    expected=not (original or deny_all or fail_label or corrupt)
    assert (result.returncode==0)==expected,(name,result.stdout,result.stderr)
    actions=events.read_text()
    if original:
        assert 'cp-denied' in actions and 'Не удалось скопировать библиотеку' in result.stderr
    else:
        assert 'cp-denied' not in actions
    if expected:
        assert 'READY_HASH_OK' in result.stdout
        if deny_primary:assert '/code_cache/cfesp-launch.' in result.stdout,result.stdout
        else:assert '/data/app/package/lib/arm64/cfesp-launch.' in result.stdout,result.stdout
    assert (native/'libunity.so').read_bytes()==b'existing game library'
    assert (native.parents[1]/'base.apk').read_bytes()==b'existing game APK'
    assert list(native.iterdir())==[native/'libunity.so']
    assert list(cache.iterdir())==[]
    assert not runtime.exists(),'temporary runtime leaked'
    report={'case':name,'expected_success':expected,'passed':True,'existing_game_files_preserved':True,
            'temporary_files_cleaned':True,'android_selinux_modelled':True,
            'actual_shell_filesystem_and_digest_operations':True,'full_device_tested':False}
    shutil.rmtree(directory)
    return report

def main():
    results=[run('v1_reproduces_copy_permission_denied',original=True),
             run('v2_rename_prelabelled_file_with_cp_denied'),
             run('v2_primary_denied_uses_game_code_cache',deny_primary=True),
             run('v2_all_locations_denied_stops_cleanly',deny_all=True),
             run('v2_selinux_disabled',disabled=True),
             run('v2_relabel_denied_stops_cleanly',fail_label=True),
             run('v2_corrupted_payload_rejected',corrupt=True)]
    (ROOT/'placement-verification.json').write_text(json.dumps({'cases':results,'device_execution_tested':False},indent=2)+'\n')
    print('Shell placement: reproduced v1 copy denial; v2 staging, fallback, integrity, refusal and cleanup cases passed')

if __name__=='__main__':main()
