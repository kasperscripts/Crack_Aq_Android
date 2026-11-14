#!/usr/bin/env python3
"""Change the fixed local key and Telegram strings, retaining native control flow."""
from pathlib import Path
import base64, hashlib, json, re

ROOT = Path(__file__).resolve().parent
MOVES = [
    (0, '1ba88ad2', '1b2889d2'),
    (4, 'bb4dacf2', '7becadf2'),
    (8, '988c8d52', '386c8c52'),
    (16, '5baeccf2', 'dbedcbf2'),
    (40, '9b2decf2', '7b48eef2'),
    (44, '780ca072', '780da072'),
]
SOURCE_APK_SHA = 'd1b3ea2956fe787ed4f30f1a5a44d72a42697e9058386804cc454097718a220d'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def native(source, output):
    original = source.read_bytes()
    data = bytearray(original)
    signature = bytes.fromhex(MOVES[0][1] + MOVES[1][1])
    assert original.count(signature) == 1
    start = original.index(signature)
    changes = []
    for relative, before, after in MOVES:
        offset = start + relative
        assert data[offset:offset+4] == bytes.fromhex(before)
        data[offset:offset+4] = bytes.fromhex(after)
        changes.append({'offset': offset, 'before': before, 'after': after})
    replacements = [(b'https://t.me/umbreladlc', b'https://t.me/Icon_Crack'),
                    (b'@umbreladlc', b'@Icon_Crack')]
    strings = []
    for before, after in replacements:
        assert len(before) == len(after)
        matches = [m.start() for m in re.finditer(re.escape(before), data)]
        assert len(matches) == (2 if before.startswith(b'https') else 1)
        for offset in matches:
            data[offset:offset+len(before)] = after
            strings.append({'offset': offset, 'before': before.decode(), 'after': after.decode()})
    assert len(data) == len(original)
    allowed = set()
    for c in changes:
        allowed.update(range(c['offset'], c['offset']+4))
    for c in strings:
        allowed.update(range(c['offset'], c['offset']+len(c['before'])))
    assert all(a == b or i in allowed for i, (a,b) in enumerate(zip(original,data)))
    assert b'umbreladlc' not in data.lower()
    output.write_bytes(data)
    return {'source_sha256': sha(original), 'target_sha256': sha(data),
            'size': len(data), 'key_load_address': start, 'key_immediate_instructions': changes,
            'telegram_strings': strings, 'branch_instructions_preserved': True,
            'all_other_native_bytes_preserved': True,
            'changed_bytes': sum(a != b for a,b in zip(original,data))}

def main():
    report = {}
    report['root'] = native(ROOT/'libcfesp.so', ROOT/'libcfesp-icon.so')
    report['nonroot'] = native(ROOT/'apk-original/lib/arm64-v8a/libumbrella.so', ROOT/'libumbrella-icon.so')
    source = (ROOT/'Umbrella-r84-beta12024-original.sh').read_text()
    pattern = r"(base64 -d > \"\$RUNTIME/libcfesp.so\" <<'CFESP_LIBRARY_PAYLOAD'\n)(.*?)(\nCFESP_LIBRARY_PAYLOAD)"
    matches = list(re.finditer(pattern, source, re.S)); assert len(matches) == 1
    payload = base64.b64encode((ROOT/'libcfesp-icon.so').read_bytes()).decode()
    payload = '\n'.join(payload[i:i+76] for i in range(0,len(payload),76))
    result = re.sub(pattern, lambda m: m[1]+payload+m[3], source, flags=re.S)
    old, new = report['root']['source_sha256'], report['root']['target_sha256']
    assert result.count(old) == 2
    result = result.replace(old,new).replace('Umbrella-r84-beta12024.sh','Umbrella_r84_Icon_Crack_root.sh')
    result = result.replace('set -eu\n','# @Icon_Crack | https://t.me/Icon_Crack\nset -eu\n',1)
    needle = "            'Требуются Android ARM64, root и установленная Oxide.' \\\n"
    assert result.count(needle) == 1
    result = result.replace(needle,needle+"            'Ключ: @Icon_Crack | Telegram: https://t.me/Icon_Crack' \\\n")
    output = ROOT/'Umbrella_r84_Icon_Crack_root.sh'; output.write_text(result); output.chmod(0o755)
    report['root_script'] = {'filename': output.name, 'size': output.stat().st_size,
        'source_sha256': sha(source.encode()), 'sha256': sha(result.encode()),
        'injector_unchanged': True, 'library_hash_checks_updated': 2,
        'game_process_and_injection_logic_preserved': True}
    p = ROOT/'smali7/io/umbrealvirtual/r72/UmbrellaUi.smali'
    s = p.read_text()
    assert s.count('@umbreladlc') == 1 and s.count('https://t.me/umbreladlc') == 2
    s = s.replace('@umbreladlc','@Icon_Crack').replace('https://t.me/umbreladlc','https://t.me/Icon_Crack')
    needle = 'const-string v9, "Umbrella"'; assert s.count(needle) == 1
    s = s.replace(needle,'const-string v9, "Umbrella · @Icon_Crack"')
    needle = '"\\nr84"'; assert s.count(needle) == 1
    s = s.replace(needle,'"\\nr84\\ncracked by @Icon_Crack"')
    p.write_text(s)
    (ROOT/'native-patch-verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print('Updated both native keys, Telegram strings, root payload hashes and APK launcher labels')

if __name__ == '__main__':
    main()
