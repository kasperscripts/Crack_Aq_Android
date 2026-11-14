import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;
import java.util.jar.*;

class VerifyJarSign {
    public static void main(String[] args)throws Exception {
        boolean unsigned=args.length>1&&args[1].equals("expect-unsigned");
        String expected="1e08a903aef9c3a721510b64ec764d01d3d094eb954161b62544ea8f187b5953";
        int count=0;
        try(JarFile jar=new JarFile(args[0],true)) {
            Enumeration<JarEntry> entries=jar.entries();
            byte[] buffer=new byte[65536];
            while(entries.hasMoreElements()) {
                JarEntry entry=entries.nextElement();
                if(entry.isDirectory()||entry.getName().startsWith("META-INF/"))continue;
                try(InputStream input=jar.getInputStream(entry)) {
                    while(input.read(buffer)!=-1) {}
                }
                Certificate[] certificates=entry.getCertificates();
                if(unsigned) {
                    if(certificates!=null&&certificates.length!=0)throw new AssertionError("Unexpected JAR signature");
                    System.out.println("{\"legacy_jar_certificate_detected\":false,\"expected_absence_confirmed\":true}");
                    return;
                }
                if(certificates==null||certificates.length==0)throw new AssertionError("Unsigned entry: "+entry.getName());
                String digest=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificates[0].getEncoded()));
                if(!digest.equals(expected))throw new AssertionError("Unexpected certificate");
                count++;
            }
        }
        if(unsigned||count==0)throw new AssertionError("No entries checked");
        System.out.println("{\"legacy_jar_certificate_detected\":true,\"all_non_metadata_entries_signed\":true,\"verified_entry_count\":"+count+",\"certificate_sha256\":\""+expected+"\"}");
    }
}
