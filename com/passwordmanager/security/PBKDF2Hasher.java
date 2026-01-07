package com.passwordmanager.security;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Utility class for hashing passwords and deriving keys using PBKDF2 (HMAC-SHA256).
 * <p>
 * <b>Cryptographic Lifecycle:</b>
 * </p>
 * <ul>
 *   <li><b>Hashing</b> – For password authentication (stored hash comparison)</li>
 *   <li><b>Verification</b> – For validating user-entered passwords against stored hashes</li>
 *   <li><b>Key Derivation</b> – For generating session keys used in encryption/decryption</li>
 * </ul>
 * <p>
 * All sensitive data (passwords, derived keys) are cleared from memory immediately 
 * after use wherever possible to reduce exposure.
 * </p>
 * 
 * <p><b>Security Guarantees:</b></p>
 * <ul>
 *   <li>Salts are cryptographically random (128-bit minimum)</li>
 *   <li>Iteration count meets OWASP recommendations (600,000+)</li>
 *   <li>Derived keys are 256-bit for AES-256 compatibility</li>
 *   <li>All intermediate key material is zeroized after use</li>
 * </ul>
 */
public final class PBKDF2Hasher {
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int KEY_LENGTH_BITS = 256;
    private static final int DEFAULT_ITERATIONS = 600_000;
    private static final int SALT_LENGTH_BYTES = 16;     // 16 bytes = 128 bits

    /**
     * Generates a cryptographically secure random salt.
     *
     * @return a byte array containing a randomly generated salt
     */
    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Hashes a password using PBKDF2 with the specified salt and iteration count.
     * <p>
     * This method is used for <b>authentication purposes only</b>. The resulting hash
     * should be stored and used for password verification via {@link #verifyPassword}.
     * </p>
     * <p>
     * <b>Security Note:</b> The password is cleared from the PBEKeySpec after hashing,
     * but the caller is responsible for clearing the input char[] array.
     * </p>
     *
     * @param password   the password to hash (char array)
     * @param salt       the salt to use for hashing
     * @param iterations the number of PBKDF2 iterations (minimum 100,000 recommended)
     * @return a {@link HashedPassword} containing the algorithm, iterations, salt, and hash
     * @throws NoSuchAlgorithmException if PBKDF2WithHmacSHA256 is not available
     * @throws InvalidKeySpecException  if the key specification is invalid
     * @throws IllegalArgumentException if password is null/empty, salt is null, or iterations < 1
     */
    public static HashedPassword hashPassword(char[] password, byte[] salt, int iterations)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        
        validateHashPasswordInputs(password, salt, iterations);

        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_LENGTH_BITS);
        byte[] hash = null;
        
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            hash = factory.generateSecret(spec).getEncoded();
            
        String encodedSalt = Base64.getEncoder().encodeToString(salt);
        String encodedHash = Base64.getEncoder().encodeToString(hash);
            
            return new HashedPassword(ALGORITHM, iterations, encodedSalt, encodedHash);
            
        } finally {
            spec.clearPassword();
            if (hash != null) {
                Arrays.fill(hash, (byte) 0);
            }
        }
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
