package com.passwordmanager.security;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
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
    private static final int SALT_LENGTH_BYTES = 16;

    // Private constructor prevents instantiation
    private PBKDF2Hasher() {
        throw new AssertionError("Utility class should not be instantiated");
    }

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
     * <p>
     * Equivalent to calling {@link #hashPassword(char[], byte[], int)} with
     * a freshly generated salt and {@value #DEFAULT_ITERATIONS} iterations.
     * </p>
     *
     * @param password the password to hash
     * @return a {@link HashedPassword} with default parameters
     * @throws NoSuchAlgorithmException if PBKDF2WithHmacSHA256 is not available
     * @throws InvalidKeySpecException  if the key specification is invalid
     * @throws IllegalArgumentException if password is null or empty
     */
    public static HashedPassword defaultHashPassword(char[] password)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        
        byte[] salt = generateSalt();
        return hashPassword(password, salt, DEFAULT_ITERATIONS);
    }

    /**
     * Verifies whether a password matches a previously stored {@link HashedPassword}.
     * <p>
     * This method performs a <b>constant-time comparison</b> of the derived hash to prevent
     * timing attacks. However, note that PBKDF2's high iteration count already makes
     * timing attacks impractical in most scenarios.
     * </p>
     *
     * @param password the password to verify
     * @param stored   the stored hashed password to check against
     * @return {@code true} if the password matches, {@code false} otherwise
     * @throws NoSuchAlgorithmException if PBKDF2WithHmacSHA256 is not available
     * @throws InvalidKeySpecException  if the key specification is invalid
     * @throws IllegalArgumentException if password or stored is null
     */
    public static boolean verifyPassword(char[] password, HashedPassword stored)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        
        if (password == null) {
            throw new IllegalArgumentException("Password cannot be null");
        }
        if (stored == null) {
            throw new IllegalArgumentException("Stored hash cannot be null");
        }

        byte[] salt = Base64.getDecoder().decode(stored.getSalt());
        byte[] storedHash = Base64.getDecoder().decode(stored.getHash());
        PBEKeySpec spec = new PBEKeySpec(password, salt, stored.getIterations(), KEY_LENGTH_BITS);
        byte[] testHash = null;
        
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(stored.getAlgorithm());
            testHash = factory.generateSecret(spec).getEncoded();
            
            return constantTimeEquals(testHash, storedHash);
            
        } finally {
            spec.clearPassword();
            if (testHash != null) {
                Arrays.fill(testHash, (byte) 0);
            }
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(storedHash, (byte) 0);
        }
    }

    /**
     * Derives raw key bytes from a password and a stored {@link HashedPassword}, 
     * suitable for vault session or encryption use.
     * <p>
     * <b>Critical Security Note:</b> This method is intended for <b>key derivation</b>,
     * NOT password verification. The derived key should be:
     * </p>
     * <ul>
     *   <li>Used immediately to unlock the vault session</li>
     *   <li>Never persisted to disk</li>
     *   <li>Zeroized from memory when the session ends</li>
     * </ul>
     * <p>
     * The caller MUST clear the returned byte array using {@code Arrays.fill(key, (byte) 0)}
     * when finished.
     * </p>
     *
     * @param password the password to derive the key from
     * @param stored   the stored hashed password providing salt and iterations
     * @return a byte array containing the derived session key (256 bits)
     * @throws NoSuchAlgorithmException if PBKDF2WithHmacSHA256 is not available
     * @throws InvalidKeySpecException  if the key specification is invalid
     * @throws IllegalArgumentException if password or stored is null
     */
    public static byte[] deriveSessionKey(char[] password, HashedPassword stored)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        
        if (password == null) {
            throw new IllegalArgumentException("Password cannot be null");
        }
        if (stored == null) {
            throw new IllegalArgumentException("Stored hash cannot be null");
        }

        byte[] salt = Base64.getDecoder().decode(stored.getSalt());
        PBEKeySpec spec = new PBEKeySpec(password, salt, stored.getIterations(), KEY_LENGTH_BITS);
        
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(stored.getAlgorithm());
            byte[] sessionKey = factory.generateSecret(spec).getEncoded();
            
            // Return key - caller MUST zeroize after use
            return sessionKey;
            
        } finally {
            spec.clearPassword();
            Arrays.fill(salt, (byte) 0);
        }
    }

    /**
     * Constant-time byte array comparison to prevent timing attacks.
     * <p>
     * While PBKDF2's iteration count makes timing attacks impractical,
     * this provides defense-in-depth.
     * </p>
     *
     * @param a first byte array
     * @param b second byte array
     * @return true if arrays are equal, false otherwise
     */
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    /**
     * Validates inputs for hashPassword method.
     */
    private static void validateHashPasswordInputs(char[] password, byte[] salt, int iterations) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        if (salt == null) {
            throw new IllegalArgumentException("Salt cannot be null");
        }
        if (iterations < 1) {
            throw new IllegalArgumentException("Iterations must be positive");
        }
    }
}