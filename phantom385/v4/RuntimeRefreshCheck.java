import dev.icon.RuntimeAsset;
import dev.phantom.l.z;
import java.nio.file.*;
import java.io.*;
import org.json.JSONObject;

class RuntimeRefreshCheck {
 static Class<?> subject;
 static boolean needs()throws Exception{return (Boolean)subject.getMethod("needsLuluRefresh",android.content.Context.class).invoke(null,new Object[]{null});}
 static void check(boolean b,String message){if(!b)throw new AssertionError(message);}
 static void reset()throws Exception{java.lang.reflect.Field f=subject.getDeclaredField("attemptedRefresh");f.setAccessible(true);f.set(null,null);}
 public static void main(String[] args)throws Exception{
  final byte[] implementation;
  try(java.util.jar.JarFile jar=new java.util.jar.JarFile(args[2])){try(InputStream in=jar.getInputStream(jar.getJarEntry("dev/icon/RuntimeAsset.class"))){implementation=in.readAllBytes();}}
  ClassLoader actual=new ClassLoader(RuntimeRefreshCheck.class.getClassLoader()){
   protected Class<?> loadClass(String name,boolean resolve)throws ClassNotFoundException{
    if(name.equals("dev.icon.RuntimeAsset")){Class<?> c=findLoadedClass(name);if(c==null)c=defineClass(name,implementation,0,implementation.length);if(resolve)resolveClass(c);return c;}return super.loadClass(name,resolve);
   }
  };
  subject=actual.loadClass("dev.icon.RuntimeAsset");
  Path work=Files.createTempDirectory(Paths.get(args[1]),"installed-runtime-");Path platform=work.resolve("libkxqpplatform.so");Files.write(platform,new byte[64]);z.platform=platform.toFile();
  Path directory=work.resolve("phantom_nonroot");Files.createDirectories(directory);Path runtime=directory.resolve("runtime-previous");Files.createDirectories(runtime);Path index=directory.resolve("install.json");
  JSONObject state=new JSONObject().put("schema",1).put("originalSha256","10020d20631ce44f00f106ed8e81a6a731deba217bfbb79d54f20e10584e3787").put("runtime",runtime.toString()).put("restored",false);
  Files.write(index,state.toString().getBytes("UTF-8"));Files.write(runtime.resolve("bootstrap.bin"),Files.readAllBytes(Paths.get(args[0]).resolve("bootstrap-final.bin")));
  check(!needs(),"current runtime scheduled for refresh");
  Files.write(runtime.resolve("bootstrap.bin"),new byte[]{1,2,3});check(needs(),"stale installed runtime missed");check(!needs(),"refresh retry loop");
  reset();state.put("restored",true);Files.write(index,state.toString().getBytes("UTF-8"));check(!needs(),"restore preference overridden");
  reset();state.put("restored",false).put("runtime",work.resolve("outside").toString());Files.write(index,state.toString().getBytes("UTF-8"));check(!needs(),"untrusted runtime path accepted");
  reset();state.put("runtime",runtime.toString()).put("originalSha256","unexpected");Files.write(index,state.toString().getBytes("UTF-8"));check(!needs(),"untrusted installation accepted");
  reset();Files.delete(index);check(!needs(),"automatic first installation");
  Files.write(Paths.get(args[0]).resolve("runtime-refresh-verification.json"),"{\"current_runtime_kept\":true,\"stale_installed_runtime_detected\":true,\"one_attempt_per_process\":true,\"restored_preference_respected\":true,\"runtime_path_validated\":true,\"original_platform_identity_checked\":true,\"fresh_install_not_automatic\":true,\"actual_lulubox_preparation_executed\":false}\n".getBytes("UTF-8"));
  System.out.println("Actual DEX refresh decision: current/stale runtime, no retry loop, restored state and path validation passed");
 }
}
