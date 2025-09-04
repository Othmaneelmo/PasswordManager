import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PBKDF2Hasher {
    private static final int KEY_LENGTH = 256;     // in bits
    private static final int DEFAULT_ITERATIONS = 600_000;
    private static final int SALT_LENGTH = 16;     // 16 bytes = 128 bits

    // Generate a random salt (16 bytes)
    public static byte[] generateSalt() {
        SecureRandom saltGenerator = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        saltGenerator.nextBytes(salt);
        return salt;
    }

    // Hash a password with PBKDF2 (using provided salt and iterations)
    public static String hashPassword(char[] password, byte[] salt, int iterations)
    throws NoSuchAlgorithmException, InvalidKeySpecException 
    {

        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_LENGTH);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hash = skf.generateSecret(spec).getEncoded();
        spec.clearPassword(); // wipe sensitive data
        return Base64.getEncoder().encodeToString(hash);
    }

    //Hash using default constants
    public static HashedPassword defaultHashPassword(char[] password)
    throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        byte[] salt = generateSalt();
        String encodedSalt = Base64.getEncoder().encodeToString(salt);
        String encodedHash = hashPassword(password, salt, DEFAULT_ITERATIONS);
        return new HashedPassword("PBKDF2WithHmacSHA256", DEFAULT_ITERATIONS, encodedSalt, encodedHash);
    }

    //verify Password
    public static boolean verifyPassword(char[] password, HashedPassword stored)
    throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        byte[] salt = Base64.getDecoder().decode(stored.getSalt());
        String testHash = hashPassword(password, salt, stored.getIterations());
        return testHash.equals(stored.getHash());
        /*
        Only using ".equals" :
        No need to use "constant time equals" to compare  inputted hash with stored hash,
        timing attacks are unrealistic with PBKDF2 hashes
        */

    }
}
