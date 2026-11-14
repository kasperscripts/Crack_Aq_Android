import dev.icon.LocalActivation;
import org.json.JSONObject;
import java.nio.file.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.nio.ByteBuffer;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;

class LocalActivationCheck {
 static class App extends android.content.Context {
  final java.io.File directory;App(Path p){directory=p.toFile();}
  public java.io.File getFilesDir(){return directory;}
  public android.content.res.AssetManager getAssets(){return null;}
 }
 static String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte a:b)s.append(String.format("%02x",a));return s.toString();}
 static void check(boolean b,String message){if(!b)throw new AssertionError(message);}
 static JSONObject request(String mode)throws Exception{return new JSONObject().put("action","activate").put("key","@Icon_Crack").put("device_id",String.join("",Collections.nCopies(32,"12"))).put("mode",mode).put("proof_nonce","000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");}
 static void denied(JSONObject r,String code)throws Exception{try{LocalActivation.reply(r);throw new AssertionError("accepted invalid request");}catch(java.io.IOException e){check(code.equals(e.getMessage()),"wrong rejection: "+e.getMessage());}}
 public static void main(String[] args)throws Exception{
  Path root=Paths.get(args[0]);
  check(hex(LocalActivation.sign(new byte[0])).equals("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),"RFC 8032 vector");
  String x509="302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
  byte[] der=new byte[x509.length()/2];for(int i=0;i<der.length;i++)der[i]=(byte)Integer.parseInt(x509.substring(2*i,2*i+2),16);
  PublicKey pk=KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
  for(String mode:new String[]{"root","nonroot"}){
   JSONObject response=LocalActivation.reply(request(mode));byte[] proof=Base64.getDecoder().decode(response.getString("proof")),sig=Base64.getDecoder().decode(response.getString("proof_signature"));
   Signature verify=Signature.getInstance("Ed25519");verify.initVerify(pk);verify.update(proof);check(verify.verify(sig),"lease signature");
   check(proof.length==304&&proof[68]==(mode.equals("root")?1:2),"proof mode");
   check(ByteBuffer.wrap(proof).getInt(296)==105,"payload release");
   JSONObject refresh=request(mode).put("action","refresh").put("token",response.getString("token"));
   check(LocalActivation.reply(refresh).getString("token").equals(response.getString("token")),"session refresh");
   check(LocalActivation.reply(request(mode).put("key"," @Icon_Crack ")).getBoolean("ok"),"trimmed key");
   denied(request(mode).put("key","@icon_crack"),"invalid_key");denied(request(mode).put("key","PH-invalid"),"invalid_key");
   denied(refresh.put("token",String.join("",Collections.nCopies(64,"0"))),"session_expired");
   Files.write(root.resolve("local-proof-"+mode+".bin"),proof);Files.write(root.resolve("local-signature-"+mode+".bin"),sig);
   JSONObject module=response.getJSONObject("module");Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
   cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(Base64.getDecoder().decode(module.getString("key")),"AES"),new GCMParameterSpec(128,Base64.getDecoder().decode(module.getString("iv"))));
   byte[] payload=cipher.doFinal(LocalActivation.encryptedPayload());check(hex(MessageDigest.getInstance("SHA-256").digest(payload)).equals(module.getString("sha256")),"payload integrity");
   Files.write(root.resolve("host-decrypted-payload.so"),payload);
  }
  Path profiles=Files.createTempDirectory(Paths.get(System.getProperty("java.io.tmpdir")),"phantom-profiles-");LocalActivation.configure(null);LocalActivation.configure(new App(profiles));
  String token=LocalActivation.reply(request("nonroot")).getString("token");
  JSONObject q=request("nonroot").put("token",token).put("name","current").put("action","profile_get");
  check(!LocalActivation.reply(q).getBoolean("found"),"new current profile");
  JSONObject config=new JSONObject().put("espOre",true).put("language","ru");
  JSONObject saved=LocalActivation.reply(q.put("action","profile_put").put("revision",0).put("config",config));check(saved.getLong("revision")==1,"profile created");
  check(LocalActivation.reply(q.put("action","profile_get")).getJSONObject("config").getBoolean("espOre"),"profile restored");
  denied(q.put("action","profile_put").put("revision",0),"profile_conflict");
  check(LocalActivation.reply(q.put("action","profile_list")).getJSONArray("profiles").length()==1,"profile list");
  LocalActivation.configureDirectory(profiles.toString());check(LocalActivation.reply(q.put("action","profile_get")).getLong("revision")==1,"profile persisted");
  check(LocalActivation.reply(q.put("action","profile_delete").put("revision",1)).getBoolean("deleted"),"profile deleted");
  check(!LocalActivation.reply(q.put("action","profile_get")).getBoolean("found"),"deleted profile absent");
  Files.write(root.resolve("local-auth-host-verification.json"),("{\"rfc8032_vector\":true,\"signed_proof\":true,\"root_and_nonroot\":true,\"trimmed_key\":true,\"wrong_keys_rejected\":true,\"session_refresh\":true,\"wrong_tokens_rejected\":true,\"payload_decryption_and_digest\":true,\"profile_save_load_delete\":true,\"profile_persistence\":true,\"profile_revision_conflicts\":true}\n").getBytes("UTF-8"));
  System.out.println("Local auth: RFC 8032, both modes, activation, refresh, rejections, payload verified");
 }
}
