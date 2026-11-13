import dev.icon.RuntimeAsset;
import android.content.Context;
import android.content.res.AssetManager;
import java.io.*;
import java.nio.file.*;
import java.util.*;

class RuntimeAssetCheck {
 static class Assets extends AssetManager {
  byte[] data;int opens;
  Assets(byte[] b){data=b;}
  public InputStream open(String name)throws IOException{if(!name.equals("bootstrap-icon.bin"))throw new IOException(name);opens++;return new ByteArrayInputStream(data);}
 }
 static class App extends Context {
  final File dir;final Assets assets;
  App(Path root,byte[] bytes)throws Exception{dir=Files.createTempDirectory(root,"cache-").toFile();assets=new Assets(bytes);}
  public File getFilesDir(){return dir;}
  public AssetManager getAssets(){return assets;}
 }
 static void check(boolean b,String s){if(!b)throw new AssertionError(s);}
 public static void main(String[] args)throws Exception{
  Path root=Paths.get(args[0]);byte[] data=Files.readAllBytes(root.resolve("bootstrap-final.bin"));App app=new App(Paths.get(args[1]),data);
  File first=RuntimeAsset.load(app);check(Arrays.equals(Files.readAllBytes(first.toPath()),data),"asset copied");check(!first.canWrite(),"cache writable");
  check(RuntimeAsset.load(app).equals(first)&&app.assets.opens==1,"cache reused");
  first.setWritable(true,true);byte[] bad=data.clone();bad[123]^=1;Files.write(first.toPath(),bad);
  check(Arrays.equals(Files.readAllBytes(RuntimeAsset.load(app).toPath()),data)&&app.assets.opens==2,"stale cache replaced");
  App invalid=new App(Paths.get(args[1]),bad);
  try{RuntimeAsset.load(invalid);throw new AssertionError("bad asset accepted");}catch(IOException expected){check(expected.getMessage().equals("runtime_download_digest"),"wrong error");}
  check(new File(invalid.dir,"server-runtime").list().length==0,"temporary file leaked");
  Files.write(root.resolve("runtime-cache-verification.json"),"{\"asset_copy\":true,\"read_only_cache\":true,\"cache_reuse\":true,\"stale_cache_replacement\":true,\"bad_asset_rejected\":true,\"temporary_file_cleanup\":true}\n".getBytes("UTF-8"));
  System.out.println("Actual DEX runtime cache: copy, read-only, reuse, replacement, tampering rejection verified");
 }
}
