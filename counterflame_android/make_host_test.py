from pathlib import Path
r=Path(__file__).parent/'host-src'
files={
'android/content/ContentResolver.java':'''package android.content; public class ContentResolver {}''',
'android/content/Context.java':'''package android.content;
import java.io.*;
public class Context { private final File root; public Context(File f){root=f;root.mkdirs();} public Context getApplicationContext(){return this;} public ContentResolver getContentResolver(){return new ContentResolver();} public File getFilesDir(){return root;} public FileInputStream openFileInput(String s)throws FileNotFoundException{return new FileInputStream(new File(root,s));} public FileOutputStream openFileOutput(String s,int mode)throws FileNotFoundException{return new FileOutputStream(new File(root,s),(mode&32768)!=0);} public boolean deleteFile(String s){return new File(root,s).delete();} }
''',
'android/provider/Settings.java':'''package android.provider; public class Settings {public static class Secure {public static String getString(android.content.ContentResolver r,String key){return "0123456789abcdef";}}}''',
'android/os/Build.java':'''package android.os; public class Build {public static class VERSION {public static String RELEASE="16";public static int SDK_INT=36;}}''',
'android/util/Base64.java':'''package android.util; public class Base64 {public static String encodeToString(byte[] v,int flags){java.util.Base64.Encoder e=(flags&8)!=0?java.util.Base64.getUrlEncoder():java.util.Base64.getEncoder();if((flags&1)!=0)e=e.withoutPadding();return e.encodeToString(v);}public static byte[] decode(String v,int flags){return ((flags&8)!=0?java.util.Base64.getUrlDecoder():java.util.Base64.getMimeDecoder()).decode(v);}}''',
'android/security/keystore/KeyGenParameterSpec.java':'''package android.security.keystore;
public class KeyGenParameterSpec implements java.security.spec.AlgorithmParameterSpec {public static class Builder {public Builder(String s,int p){} public Builder setAlgorithmParameterSpec(java.security.spec.AlgorithmParameterSpec p){return this;} public Builder setDigests(String... s){return this;} public KeyGenParameterSpec build(){return new KeyGenParameterSpec();}}}''',
'AuthHostTest.java':'''import java.io.*;import java.nio.file.*;import java.net.*;import java.lang.reflect.*;import java.util.*;import java.util.concurrent.atomic.*;
public class AuthHostTest {
 static AtomicInteger requests=new AtomicInteger();static java.net.URL jar;static List<Class<?>> all=new ArrayList<>();
 static Class<?> fresh()throws Exception {var loader=new URLClassLoader(new java.net.URL[]{jar},AuthHostTest.class.getClassLoader());var c=Class.forName("com.unity3d.player.CFAuth",true,loader);all.add(c);return c;}
 static Object call(Class<?> c,String method,Class<?>[] types,Object...args)throws Exception{return c.getMethod(method,types).invoke(null,args);}
 static Object value(Class<?> c,String method)throws Exception{return call(c,method,new Class<?>[]{});}
 static Field field(Class<?> c,String name)throws Exception {Field f=c.getDeclaredField(name);f.setAccessible(true);return f;}
 static void yes(boolean v,String msg){if(!v)throw new AssertionError(msg);}
 static Object boot(Class<?> c,android.content.Context ctx)throws Exception{return call(c,"bootstrap",new Class<?>[]{android.content.Context.class},ctx);}
 static String activate(Class<?> c,String key)throws Exception{return (String)call(c,"activate",new Class<?>[]{String.class},key);}
 public static void main(String[] args)throws Exception {
  URL.setURLStreamHandlerFactory(p->p.equals("https")?new URLStreamHandler(){protected URLConnection openConnection(URL u)throws IOException {requests.incrementAndGet();throw new IOException("Unexpected network request");}}:null);
  jar=Path.of(args[0]).toUri().toURL();Path dir=Files.createTempDirectory("cf-auth-test-");var ctx=new android.content.Context(dir.toFile());var c=fresh();
  yes(boot(c,ctx).equals("key"),"First launch must require a key");yes(!(Boolean)value(c,"hasAccess"),"No access before entry");
  yes(activate(c,"wrong-key").startsWith("err:"),"Wrong key rejected");yes(!(Boolean)value(c,"hasAccess"),"Wrong key must not enable features");
  yes(activate(c,"@Icon_Crack").equals("ok"),"Correct key accepted");yes((Boolean)value(c,"hasAccess"),"Access flag");yes(value(c,"tier").equals("vip"),"Tier initialized");yes(value(c,"featuresCsv").equals("*"),"Native feature CSV initialized");yes((Boolean)call(c,"featureAllowed",new Class<?>[]{String.class},"any-native-feature"),"Feature gates enabled");yes((Long)value(c,"licenseExpiry")==4102444799L,"License expiry initialized");yes(Files.readString(dir.resolve(".cf-l")).equals("@Icon_Crack"),"Cache keeps only the key");
  String hash=(String)value(c,"deviceHashShort");yes(hash.length()==10,"Device proof identity initialized");
  Thread thread=(Thread)field(c,"sRefreshThread").get(null);field(c,"sTokenExpiry").setLong(null,1L);var refresh=c.getDeclaredMethod("refresh");refresh.setAccessible(true);refresh.invoke(null);yes((Long)field(c,"sTokenExpiry").get(null)>System.currentTimeMillis()/1000,"Refresh renews session");yes(field(c,"sRefreshThread").get(null)==thread,"Refresh does not start another loop");yes((Boolean)value(c,"hasAccess"),"Access survives refresh");
  var restart=fresh();yes(boot(restart,ctx).equals("ok"),"Cached restart accepted");yes((Boolean)value(restart,"hasAccess"),"Cached access");yes(value(restart,"featuresCsv").equals("*"),"Cached feature gates");yes(value(restart,"deviceHashShort").equals(hash),"Device proof key persisted");
  var badCache=new android.content.Context(Files.createTempDirectory("cf-invalid-cache-").toFile());Files.writeString(new File(badCache.getFilesDir(),".cf-l").toPath(),"wrong-cached-license");var b=fresh();yes(boot(b,badCache).equals("key"),"Invalid cached key returns prompt");yes(!(Boolean)value(b,"hasAccess"),"Invalid cache gives no access");yes(!new File(badCache.getFilesDir(),".cf-l").exists(),"Invalid cache removed by original SDK");
  for(String key:new String[]{"","@Icon_Crack бай бай жирный","@icon_crack"}){var x=fresh();var xctx=new android.content.Context(Files.createTempDirectory("cf-negative-").toFile());boot(x,xctx);yes(activate(x,key).startsWith("err:"),"Only the exact key is accepted");yes(!(Boolean)value(x,"hasAccess"),"Negative key cannot open menu");}
  yes(requests.get()==0,"Local path must not use the server");
  for(Class<?> x:all){field(x,"sRefreshRun").setBoolean(null,false);Thread t=(Thread)field(x,"sRefreshThread").get(null);if(t!=null)t.interrupt();}
  System.out.println("PASS: actual patched DEX on JVM: key, VIP feature state, refresh, cached restart, persistent identity, negative keys, no network");
 }
}'''
}
for name,value in files.items():p=r/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(value+'\n')
