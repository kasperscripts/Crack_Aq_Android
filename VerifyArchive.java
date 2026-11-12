import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.zip.ZipFile;

/** Verify the complete APK with Java's independent ZIP parser/Inflater. */
public class VerifyArchive {
    public static void main(String[] args) throws Exception {
        String expected = args[1];
        long expectedSize = Long.parseLong(args[2]);
        try (ZipFile zip = new ZipFile(Path.of(args[0]).toFile())) {
            var entry = zip.getEntry("AQ_Icon_Crack.apk");
            if (entry == null || entry.getSize() != expectedSize) throw new AssertionError("APK size");
            var digest = MessageDigest.getInstance("SHA-256");
            var crc = new java.util.zip.CRC32();
            long count = 0;
            byte[] block = new byte[1024 * 1024];
            try (var input = zip.getInputStream(entry)) {
                int n;
                while ((n = input.read(block)) != -1) {
                    digest.update(block, 0, n);
                    crc.update(block, 0, n);
                    count += n;
                }
            }
            String actual = HexFormat.of().formatHex(digest.digest());
            if (count != entry.getSize() || crc.getValue() != entry.getCrc() || !actual.equals(expected))
                throw new AssertionError("APK checksum mismatch");
            System.out.println("PASS: Java ZIP extraction, " + count + " bytes, SHA-256 " + actual);
        }
    }
}
