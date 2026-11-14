package dev.icon;

import java.io.IOException;
import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import android.util.Base64;
import android.content.Context;
import org.json.JSONArray;
import org.json.JSONObject;

/** Local activation for this build; contains no original license or server token. */
public final class LocalActivation {
    private static final BigInteger P=BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger L=BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
    private static final BigInteger D=new BigInteger("37095705934669439343138083508754565189542113879843219016388785533085940283555");
    private static final BigInteger[] B=point(new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202"),new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960"));
    // RFC 8032's publicly documented test seed. This is not a server credential.
    private static final byte[] SEED=hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    private static final byte[] PUBLIC=hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    private static File profileDirectory;
    public static void configure(Context context){if(context!=null)profileDirectory=context.getFilesDir();}
    public static void configureDirectory(String path){profileDirectory=new File(path);}

    private static BigInteger mod(BigInteger a){return a.mod(P);}
    private static BigInteger[] point(BigInteger x,BigInteger y){return new BigInteger[]{x,y,BigInteger.ONE,mod(x.multiply(y))};}
    private static BigInteger[] add(BigInteger[] p,BigInteger[] q){
        BigInteger a=mod(p[1].subtract(p[0]).multiply(q[1].subtract(q[0])));
        BigInteger b=mod(p[1].add(p[0]).multiply(q[1].add(q[0])));
        BigInteger c=mod(p[3].multiply(q[3]).multiply(D).shiftLeft(1));
        BigInteger d=mod(p[2].multiply(q[2]).shiftLeft(1));
        BigInteger e=mod(b.subtract(a)),f=mod(d.subtract(c)),g=mod(d.add(c)),h=mod(b.add(a));
        return new BigInteger[]{mod(e.multiply(f)),mod(g.multiply(h)),mod(f.multiply(g)),mod(e.multiply(h))};
    }
    private static BigInteger[] mul(BigInteger k){
        BigInteger[] r=point(BigInteger.ZERO,BigInteger.ONE),a=B;
        for(int i=0;i<256;i++){if(k.testBit(i))r=add(r,a);a=add(a,a);}return r;
    }
    private static BigInteger little(byte[] b){byte[] x=b.clone();for(int i=0;i<x.length/2;i++){byte t=x[i];x[i]=x[x.length-1-i];x[x.length-1-i]=t;}return new BigInteger(1,x);}
    private static byte[] little(BigInteger n,int size){byte[] a=n.toByteArray(),r=new byte[size];for(int i=0;i<Math.min(size,a.length);i++)r[i]=a[a.length-1-i];return r;}
    private static byte[] encode(BigInteger[] p){BigInteger z=p[2].modInverse(P);BigInteger x=mod(p[0].multiply(z)),y=mod(p[1].multiply(z));byte[] out=little(y,32);if(x.testBit(0))out[31]|=(byte)128;return out;}
    private static byte[] hash(String algorithm,byte[]... b)throws Exception{MessageDigest d=MessageDigest.getInstance(algorithm);for(byte[] a:b)d.update(a);return d.digest();}
    public static byte[] sign(byte[] message)throws Exception{
        byte[] h=hash("SHA-512",SEED);h[0]&=248;h[31]&=63;h[31]|=64;
        BigInteger a=little(Arrays.copyOf(h,32));BigInteger r=little(hash("SHA-512",Arrays.copyOfRange(h,32,64),message)).mod(L);
        byte[] R=encode(mul(r));BigInteger k=little(hash("SHA-512",R,PUBLIC,message)).mod(L);byte[] S=little(r.add(k.multiply(a)).mod(L),32);
        byte[] out=new byte[64];System.arraycopy(R,0,out,0,32);System.arraycopy(S,0,out,32,32);return out;
    }
    private static byte[] hex(String s){byte[] b=new byte[s.length()/2];for(int i=0;i<b.length;i++)b[i]=(byte)Integer.parseInt(s.substring(i*2,i*2+2),16);return b;}
    private static String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte a:b){s.append(Character.forDigit((a>>>4)&15,16));s.append(Character.forDigit(a&15,16));}return s.toString();}
    private static String b64(byte[] b){return Base64.encodeToString(b,Base64.NO_WRAP);}

    public static JSONObject reply(JSONObject request)throws Exception{
        String action=request.optString("action");
        String device=request.getString("device_id"),mode=request.getString("mode");
        if(!device.matches("[0-9a-f]{64}")||!(mode.equals("root")||mode.equals("nonroot")))throw new IOException("missing_identity");
        String token=hex(hash("SHA-256",("Icon_Crack/local/v1/"+device+"/"+mode).getBytes(StandardCharsets.UTF_8)));
        if(action.startsWith("profile_")){
            if(!token.equals(request.optString("token")))throw new IOException("session_expired");
            return profile(request);
        }
        String nonce=request.getString("proof_nonce");
        if(!nonce.matches("[0-9a-f]{64}"))throw new IOException("proof_unavailable");
        if(action.equals("activate")){
            if(!"@Icon_Crack".equals(request.optString("key").trim()))throw new IOException("invalid_key");
        }else if(action.equals("refresh")){
            if(!token.equals(request.optString("token")))throw new IOException("session_expired");
        }else throw new IOException("profile_access_denied");
        long now=System.currentTimeMillis()/1000L;
        ByteBuffer p=ByteBuffer.allocate(304).order(ByteOrder.BIG_ENDIAN);
        p.put(new byte[]{'O','X','L','7'}).put(hex(nonce)).put(hex(device));
        p.put((byte)(mode.equals("root")?1:2)).put((byte)3).putShort((short)30).putLong(now+315360000L).putLong(now);
        p.put(hex(LocalPayload.SHA256));
        p.position(184);p.put(hash("SHA-256",token.getBytes(StandardCharsets.UTF_8)));
        p.position(232);p.put(hex(LocalPayload.SHA512));
        p.position(296);p.putInt(105).putInt(255);
        byte[] proof=p.array();
        JSONObject module=new JSONObject().put("ticket",token).put("sha256",LocalPayload.SHA256).put("key",LocalPayload.KEY).put("iv",LocalPayload.IV).put("encrypted_size",LocalPayload.SIZE);
        return new JSONObject().put("ok",true).put("api_version",2).put("installation_approved",true).put("token",token).put("session_ttl_seconds",30).put("license_remaining_seconds",315360000L).put("allow_root",true).put("allow_nonroot",true).put("proof",b64(proof)).put("proof_signature",b64(sign(proof))).put("signed_protocol",7).put("module",module);
    }
    public static byte[] encryptedPayload(){return LocalPayload.bytes();}
    private static synchronized JSONObject profile(JSONObject request)throws Exception{
        if(profileDirectory==null)throw new IOException("storage");
        if(!profileDirectory.isDirectory()&&!profileDirectory.mkdirs())throw new IOException("storage");
        File file=new File(profileDirectory,"icon-profiles-v1.json");JSONObject profiles=new JSONObject();
        if(file.isFile()){
            if(file.length()>1048576)throw new IOException("storage");
            FileInputStream input=new FileInputStream(file);ByteArrayOutputStream output=new ByteArrayOutputStream();
            try{byte[] buffer=new byte[8192];int n;while((n=input.read(buffer))!=-1)output.write(buffer,0,n);}finally{input.close();}
            profiles=new JSONObject(new String(output.toByteArray(),StandardCharsets.UTF_8));
        }
        String action=request.getString("action");JSONObject result=new JSONObject().put("ok",true).put("api_version",2);
        if(action.equals("profile_list")){
            JSONArray list=new JSONArray();java.util.Iterator<String> names=profiles.keys();while(names.hasNext()){String name=names.next();list.put(new JSONObject().put("name",name).put("revision",profiles.getJSONObject(name).getLong("revision")));}return result.put("profiles",list);
        }
        String name=request.optString("name");if(name.isEmpty()||name.length()>128)throw new IOException("invalid_profile_name");
        JSONObject old=profiles.optJSONObject(name);long revision=old==null?0:old.getLong("revision");
        if(action.equals("profile_get")){result.put("name",name).put("found",old!=null).put("revision",revision);if(old!=null)result.put("config",old.getJSONObject("config"));return result;}
        if(action.equals("profile_put")){
            if(request.optBoolean("create_only")&&old!=null)throw new IOException("profile_exists");
            if(request.optLong("revision")!=revision)throw new IOException("profile_conflict");
            JSONObject config=request.getJSONObject("config");profiles.put(name,new JSONObject().put("revision",revision+1).put("config",config));result.put("name",name).put("revision",revision+1).put("config",config).put("found",true);
        }else if(action.equals("profile_delete")){
            if(request.optLong("revision")!=revision)throw new IOException("profile_conflict");profiles.remove(name);result.put("deleted",old!=null);
        }else throw new IOException("profile_access_denied");
        byte[] bytes=profiles.toString().getBytes(StandardCharsets.UTF_8);if(bytes.length>1048576)throw new IOException("storage");
        File temporary=File.createTempFile("icon-profiles-",".part",profileDirectory);
        try{FileOutputStream output=new FileOutputStream(temporary);try{output.write(bytes);output.getFD().sync();}finally{output.close();}temporary.setReadable(false,false);temporary.setReadable(true,true);temporary.setWritable(false,false);temporary.setWritable(true,true);if(!temporary.renameTo(file))throw new IOException("storage");}finally{if(temporary.exists())temporary.delete();}
        return result;
    }
}
