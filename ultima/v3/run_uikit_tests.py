"""Run the actual UIKit relay on an iOS simulator, including Foundation KVC."""
import json,platform,plistlib,subprocess,sys,os
from pathlib import Path
root=Path(__file__).resolve().parent;work=Path(sys.argv[1]);app=work/'RelayTests.app';app.mkdir(exist_ok=True)
blob=(root/'alias.bin').read_bytes();expected=bytes(blob[9+i]^((0x5a+i*29)&255) for i in range(blob[8])).decode();(app/'expected.txt').write_text(expected)
bundle='com.icon.crack.relaytests';(app/'Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable':'RelayTests','CFBundleIdentifier':bundle,'CFBundleName':'RelayTests','CFBundleVersion':'1','CFBundlePackageType':'APPL','MinimumOSVersion':'15.0','LSRequiresIPhoneOS':True,'CFBundleSupportedPlatforms':['iPhoneSimulator']}))
def run(args,**kw):return subprocess.run(list(map(str,args)),check=True,**kw)
sdk=subprocess.check_output(['xcrun','--sdk','iphonesimulator','--show-sdk-path'],text=True).strip();arch='arm64' if platform.machine()=='arm64' else 'x86_64'
run(['xcrun','--sdk','iphonesimulator','clang','-target',arch+'-apple-ios15.0-simulator','-isysroot',sdk,'-I',work,'-fobjc-arc','-fblocks','-O1','-Wno-deprecated-declarations',root/'IconLink.m',root/'ICRelay.m',root/'ICPolicy.m',root/'SimulatorTests.m','-framework','Foundation','-framework','UIKit','-o',app/'RelayTests'])
all_devices=json.loads(subprocess.check_output(['xcrun','simctl','list','devices','available','-j']))['devices'];candidates=[]
for runtime,devices in all_devices.items():
 if '.iOS-' in runtime:
  candidates.extend(d for d in devices if d.get('isAvailable') and d['name'].startswith('iPhone'))
assert candidates,'No installed iOS simulator runtime'
device=candidates[0]['udid'];started=False
try:
 if candidates[0]['state']!='Booted':run(['xcrun','simctl','boot',device]);started=True
 run(['xcrun','simctl','bootstatus',device,'-b'],timeout=300)
 run(['xcrun','simctl','install',device,app],timeout=120)
 result=run(['xcrun','simctl','launch','--console','--terminate-running-process',device,bundle],capture_output=True,text=True,timeout=120)
 assert 'IC_UIKIT_PASS' in result.stdout,'UIKit relay did not pass; see the result file'
 container=Path(subprocess.check_output(['xcrun','simctl','get_app_container',device,bundle,'data'],text=True).strip());report=json.loads((container/'Documents/relay-tests.json').read_text());assert report and all(report.values()),report
 (work/'uikit-relay-verification.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS: UIKit, factory, cache and pre-encryption JSON relay including startup without input',flush=True)
finally:
 if started:subprocess.run(['xcrun','simctl','shutdown',device],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
