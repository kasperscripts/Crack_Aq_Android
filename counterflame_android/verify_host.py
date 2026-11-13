from pathlib import Path
import argparse,json,os,subprocess
p=argparse.ArgumentParser();p.add_argument('tools',type=Path);a=p.parse_args();root=Path(__file__).parent;v=json.loads((root/'host-tool-versions.json').read_text());env=dict(os.environ);env['PYTHONPATH']=str(a.tools/('enjarify-'+v['enjarify_commit']));jar=root/'auth-verified.jar'
subprocess.run(['python3','-m','enjarify.main',str(root/'classes3-icon.dex'),'-o',str(jar),'-f'],check=True,env=env)
subprocess.run(['python3',str(root/'make_host_test.py')],check=True);classes=root/'host-classes';classes.mkdir(exist_ok=True)
subprocess.run(['java','-m','jdk.compiler/com.sun.tools.javac.Main','-d',str(classes),*[str(p) for p in sorted((root/'host-src').rglob('*.java'))]],check=True)
subprocess.run(['java','-Xverify:all','-cp',str(classes)+os.pathsep+str(a.tools/'json.jar'),'AuthHostTest',str(jar)],check=True)
r={'actual_signed_apk_dex_executed_on_jvm':True,'key':'@Icon_Crack','only_exact_key_accepted':True,'new_install_requires_key':True,'vip_tier_and_all_native_feature_gates_initialized':True,'native_feature_csv':'*','license_expiry':4102444799,'session_refresh_verified':True,'one_refresh_loop_preserved':True,'cached_restart_verified':True,'device_proof_identity_persisted':True,'invalid_cache_returns_key_prompt':True,'no_license_server_requests':True,'provided_paid_key_embedded':False,'physical_android_device_tested':False};(root/'auth-verification.json').write_text(json.dumps(r,indent=2)+'\n')
