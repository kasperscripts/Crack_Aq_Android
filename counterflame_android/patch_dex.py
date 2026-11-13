from pathlib import Path
import json,re,shutil
ROOT=Path(__file__).parent
source=ROOT/'smali3';target=ROOT/'patched-smali3';shutil.copytree(source,target,dirs_exist_ok=True)
p=target/'com/unity3d/player/CFAuth.smali';text=p.read_text()
profile={'ok':True,'access_token':'@Icon_Crack','expires_in':300,'refresh_after':60,'license':{'tier':'vip','expires_at':4102444799,'features':None}}
router=''' .method private static post(Ljava/lang/String;Lorg/json/JSONObject;)Lorg/json/JSONObject;
    .registers 6
    const-string v0, "/api/v2/devices/configuration"
    invoke-virtual {v0, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v0
    if-eqz v0, :status
    const-string v0, "{\\"ok\\":true,\\"require_key\\":true,\\"maintenance\\":false}"
    goto :parse
:status
    const-string v0, "/api/v2/devices/status"
    invoke-virtual {v0, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v0
    if-eqz v0, :challenge
    const-string v0, "{\\"ok\\":true,\\"registered\\":true}"
    goto :parse
:challenge
    const-string v0, "/api/v2/devices/challenge"
    invoke-virtual {v0, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v0
    if-nez v0, :nonce
    const-string v0, "/api/v2/licenses/challenge"
    invoke-virtual {v0, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v0
    if-eqz v0, :activate
:nonce
    new-instance v0, Lorg/json/JSONObject;
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V
    const-string v1, "ok"
    const/4 v2, 0x1
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;
    const-string v1, "nonce"
    const/16 v2, 0x10
    invoke-static {v2}, Lcom/unity3d/player/CFAuth;->randomHex(I)Ljava/lang/String;
    move-result-object v2
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;
    return-object v0
:activate
    const-string v0, "/api/v2/licenses/activate"
    invoke-virtual {v0, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v0
    if-eqz v0, :refresh
    const-string v0, "license_key"
    goto :key
:refresh
    const-string v0, "/api/v2/sessions/refresh"
    invoke-virtual {v0, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v0
    if-eqz v0, :denied
    const-string v0, "access_token"
:key
    invoke-virtual {p1, v0}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    const-string v0, "@Icon_Crack"
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v0
    if-eqz v0, :denied
    const-string v0, PROFILE
:parse
    new-instance v1, Lorg/json/JSONObject;
    invoke-direct {v1, v0}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V
    return-object v1
:denied
    new-instance v0, Lcom/unity3d/player/CFAuth$AuthError;
    const-string v1, "Неверный ключ."
    const/4 v2, 0x1
    invoke-direct {v0, v1, v2}, Lcom/unity3d/player/CFAuth$AuthError;-><init>(Ljava/lang/String;Z)V
    throw v0
.end method'''.replace('PROFILE',json.dumps(json.dumps(profile,separators=(',',':')),ensure_ascii=False)).strip()
text,n=re.subn(r'(?ms)^\.method private static post\(Ljava/lang/String;Lorg/json/JSONObject;\)Lorg/json/JSONObject;\n.*?^\.end method',lambda _:router,text);assert n==1;p.write_text(text)
p=target/'com/unity3d/player/CFAuthUI.smali';text=p.read_text();mapping={'https://t.me/RAVENiOSPORTAL':'https://t.me/Icon_Crack','RAVEN':'@Icon_Crack бай бай жирный','RAVEN Licensing':'@Icon_Crack бай бай жирный'}
for old,new in mapping.items():
 old=json.dumps(old,ensure_ascii=False);new=json.dumps(new,ensure_ascii=False);assert old in text,old;text=text.replace(old,new)
p.write_text(text)
(ROOT/'dex-patch-report.json').write_text(json.dumps({'key':'@Icon_Crack','display':'@Icon_Crack бай бай жирный','replaced_auth_method':'CFAuth.post','original_bootstrap_activation_apply_session_and_refresh_retained':True,'profile':profile,'java_telegram_target':'https://t.me/Icon_Crack'},ensure_ascii=False,indent=2)+'\n')
print('Patched SDK request router and UI branding')
