import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PBKDF2Hasher {
    private static final int KEY_LENGTH = 256; // key length in bits

    // Generate a random salt (16 bytes)
    public static byte[] generateSalt() {
        SecureRandom saltGenerator = new SecureRandom();
        byte[] salt = new byte[16];
        saltGenerator.nextBytes(salt);
        return salt;
    }

    // Hash a password with PBKDF2
    public static String hashPassword(char[] password, byte[] salt, int iterations)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_LENGTH);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hash = skf.generateSecret(spec).getEncoded();
        spec.clearPassword(); // wipe sensitive data
        return Base64.getEncoder().encodeToString(hash);
    }
}
