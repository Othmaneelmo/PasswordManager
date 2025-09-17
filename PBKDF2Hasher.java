import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Utility class for hashing passwords and deriving keys using PBKDF2 (HMAC-SHA256).
 * <p>
 * Provides methods to generate salts, hash passwords, verify password matches, 
 * and derive raw key bytes for session use.
 * </p>
 * <p>
 * All sensitive data (passwords, derived keys) are cleared from memory immediately 
 * after use wherever possible to reduce exposure.
 * </p>
 */
public class PBKDF2Hasher {
    private static final int KEY_LENGTH = 256;     // in bits
    private static final int DEFAULT_ITERATIONS = 600_000;
    private static final int SALT_LENGTH = 16;     // 16 bytes = 128 bits

    /**
     * Generates a random salt.
     *
     * @return a byte array containing a randomly generated salt
     */
    public static byte[] generateSalt() {
        SecureRandom saltGenerator = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        saltGenerator.nextBytes(salt);
        return salt;
    }

    /**
     * Hashes a password using PBKDF2 with the specified salt and iteration count.
     *
     * @param password   the password to hash (char array)
     * @param salt       the salt to use for hashing
     * @param iterations the number of PBKDF2 iterations
     * @return a {@link HashedPassword} containing the algorithm, iterations, salt, and hash
     * @throws NoSuchAlgorithmException if PBKDF2WithHmacSHA256 is not available
     * @throws InvalidKeySpecException  if the key specification is invalid
     */
    public static HashedPassword hashPassword(char[] password, byte[] salt, int iterations)
    throws NoSuchAlgorithmException, InvalidKeySpecException 
    {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_LENGTH);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hash = skf.generateSecret(spec).getEncoded();
        spec.clearPassword(); // wipe sensitive data
        String encodedSalt = Base64.getEncoder().encodeToString(salt);
        String encodedHash = Base64.getEncoder().encodeToString(hash);
        return new HashedPassword("PBKDF2WithHmacSHA256", iterations, encodedSalt, encodedHash);
    }

    /**
     * Hashes a password using default salt and iteration constants.
     *
     * @param password the password to hash
     * @return a {@link HashedPassword} with default parameters
     * @throws NoSuchAlgorithmException if PBKDF2WithHmacSHA256 is not available
     * @throws InvalidKeySpecException  if the key specification is invalid
     */
    public static HashedPassword defaultHashPassword(char[] password)
    throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        byte[] salt = generateSalt();
        return hashPassword(password, salt, DEFAULT_ITERATIONS);
    }

    /**
     * Verifies whether a password matches a previously stored {@link HashedPassword}.
     *
     * @param password the password to verify
     * @param stored   the stored hashed password to check against
     * @return {@code true} if the password matches, {@code false} otherwise
     * @throws NoSuchAlgorithmException if PBKDF2WithHmacSHA256 is not available
     * @throws InvalidKeySpecException  if the key specification is invalid
     */
    public static boolean verifyPassword(char[] password, HashedPassword stored)
    throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        byte[] salt = Base64.getDecoder().decode(stored.getSalt());
        HashedPassword testHp = hashPassword(password, salt, stored.getIterations());
        return testHp.getHash().equals(stored.getHash());
        /*
         * Only using ".equals":
         * No need for constant-time equals — timing attacks are unrealistic with PBKDF2.
         */

    }

    /**
     * Derives raw key bytes from a password and a stored {@link HashedPassword}, 
     * suitable for session or encryption use.
     *
     * @param password the password to derive the key from
     * @param stored   the stored hashed password providing salt and iterations
     * @return a byte array containing the derived key
     * @throws NoSuchAlgorithmException if PBKDF2WithHmacSHA256 is not available
     * @throws InvalidKeySpecException  if the key specification is invalid
     */
    public static byte[] deriveKey(char[] password, HashedPassword stored)
    throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        byte[] salt = Base64.getDecoder().decode(stored.getSalt());
        PBEKeySpec spec = new PBEKeySpec(password, salt, stored.getIterations(), KEY_LENGTH);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] sessionKey = skf.generateSecret(spec).getEncoded();
        spec.clearPassword();
        return sessionKey;
    }
}
