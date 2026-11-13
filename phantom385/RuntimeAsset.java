package dev.icon;
import android.content.Context;
import java.io.*;
import java.security.MessageDigest;

public final class RuntimeAsset {
    private static final String EXPECTED="BUNDLE_SHA256";
    private static boolean valid(File file)throws Exception{
        if(!file.isFile()||file.length()!=BUNDLE_SIZE)return false;
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        InputStream input=new FileInputStream(file);
        try{byte[] b=new byte[16384];int n;while((n=input.read(b))!=-1)digest.update(b,0,n);}finally{input.close();}
        StringBuilder s=new StringBuilder();for(byte b:digest.digest()){s.append(Character.forDigit((b>>>4)&15,16));s.append(Character.forDigit(b&15,16));}
        return EXPECTED.equals(s.toString());
    }
    public static synchronized File load(Context context)throws Exception{
        File directory=new File(context.getFilesDir(),"server-runtime");
        if(!directory.isDirectory()&&!directory.mkdirs())throw new IOException("runtime_cache_create");
        File target=new File(directory,"bootstrap.bin");if(valid(target))return target;
        File temporary=File.createTempFile("icon-runtime-",".part",directory);
        try{
            InputStream input=context.getAssets().open("bootstrap-icon.bin");
            try{
                FileOutputStream output=new FileOutputStream(temporary);
                try{byte[] b=new byte[16384];int n;long total=0;while((n=input.read(b))!=-1){total+=n;if(total>BUNDLE_SIZE)throw new IOException("runtime_package_size");output.write(b,0,n);}output.getFD().sync();}finally{output.close();}
            }finally{input.close();}
            if(!valid(temporary))throw new IOException("runtime_download_digest");
            if(!temporary.setReadable(false,false)||!temporary.setReadable(true,true)||!temporary.setWritable(false,false))throw new IOException("runtime_cache_permissions");
            if(!temporary.renameTo(target))throw new IOException("runtime_assets_commit");
            return target;
        }finally{if(temporary.exists())temporary.delete();}
    }
}
