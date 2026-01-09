package com.passwordmanager.crypto;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

/**
 * Interface for authenticated encryption operations.
 * <p>
 * Implementations must provide:
 * </p>
 * <ul>
 *   <li><b>Authenticated Encryption with Associated Data (AEAD)</b></li>
 *   <li><b>Automatic IV/nonce generation</b> (never reused)</li>
 *   <li><b>Key size validation</b> against the security profile</li>
 *   <li><b>Thread-safe operations</b></li>
 * </ul>
 * 
 * <p><b>Design Principles:</b></p>
 * <ul>
 *   <li>Stateless - no internal state between operations</li>
 *   <li>Explicit - all parameters visible in method signatures</li>
 *   <li>Fail-safe - throws exceptions rather than returning invalid data</li>
 *   <li>Algorithm-agnostic - supports any AEAD cipher</li>
 * </ul>
 * 
 * <p><b>Security Contract:</b></p>
 * <ul>
 *   <li>IVs MUST be unique for every encryption with the same key</li>
 *   <li>Authentication tags MUST be verified before returning plaintext</li>
 *   <li>Keys MUST match the profile's required size</li>
 *   <li>Failed authentication MUST throw exceptions, not return partial data</li>
 * </ul>
 * 
 * <p><b>Thread Safety:</b></p>
 * <p>
 * Implementations must be thread-safe. Multiple threads may encrypt/decrypt
 * concurrently using the same provider instance.
 * </p>
 * 
 * <p><b>Example Usage:</b></p>
 * <pre>
 * SecretKey sessionKey = VaultSession.getVaultSessionKey();
 * EncryptionProvider provider = new AesGcmProvider(SecurityProfile.BALANCED);
 * 
 * // Encrypt
 * byte[] plaintext = "secret data".getBytes(StandardCharsets.UTF_8);
 * EncryptionResult result = provider.encrypt(plaintext, sessionKey);
 * 
 * // Decrypt
 * byte[] decrypted = provider.decrypt(result, sessionKey);
 * 
 * // Cleanup
 * Arrays.fill(plaintext, (byte) 0);
 * Arrays.fill(decrypted, (byte) 0);
 * </pre>
 * 
 * <p><b>Future Extensions:</b></p>
 * <p>
 * This interface can be extended to support:
 * - Streaming encryption for large files
 * - Associated data (AAD) for context binding
 * - Key rotation and re-encryption
 * - Compression before encryption
 * </p>
 */
public interface EncryptionProvider {
    /**
     * Encrypts plaintext using authenticated encryption.
     * <p>
     * <b>Guarantees:</b>
     * </p>
     * <ul>
     *   <li>Generates a cryptographically random IV/nonce</li>
     *   <li>IV is unique and never reused</li>
     *   <li>Returns ciphertext with embedded authentication tag</li>
     *   <li>Original plaintext is NOT modified</li>
     * </ul>
     * <p>
     * <b>Caller Responsibilities:</b>
     * </p>
     * <ul>
     *   <li>Zeroize plaintext array after encryption if sensitive</li>
     *   <li>Store the returned EncryptionResult securely</li>
     *   <li>Use the same key for decryption</li>
     * </ul>
     *
     * @param plaintext the data to encrypt (must not be null or empty)
     * @param key the encryption key (must match profile's key size)
     * @return an {@link EncryptionResult} containing IV and ciphertext
     * @throws IllegalArgumentException if plaintext is null/empty or key is invalid
     * @throws GeneralSecurityException if encryption fails
     */
    EncryptionResult encrypt(byte[] plaintext, SecretKey key) 
            throws GeneralSecurityException;

    /**
     * Decrypts an encrypted result using authenticated decryption.
     * <p>
     * <b>Security Guarantees:</b>
     * </p>
     * <ul>
     *   <li>Verifies authentication tag before returning plaintext</li>
     *   <li>Throws exception if tag verification fails (tampering detected)</li>
     *   <li>Returns plaintext only if authentication succeeds</li>
     * </ul>
     * <p>
     * <b>Caller Responsibilities:</b>
     * </p>
     * <ul>
     *   <li>Zeroize returned plaintext after use</li>
     *   <li>Handle authentication failures appropriately</li>
     *   <li>Use the same key that was used for encryption</li>
     * </ul>
     *
     * @param encrypted the encryption result to decrypt
     * @param key the decryption key (must match encryption key)
     * @return the decrypted plaintext
     * @throws IllegalArgumentException if encrypted is null or key is invalid
     * @throws GeneralSecurityException if decryption fails or authentication fails
     */
    byte[] decrypt(EncryptionResult encrypted, SecretKey key) 
            throws GeneralSecurityException;

    /**
     * Returns the security profile used by this provider.
     * <p>
     * The profile determines all cryptographic parameters including
     * algorithm, key size, IV size, and tag size.
     * </p>
     *
     * @return the security profile
     */
    SecurityProfile getProfile();

    /**
     * Validates that a key is compatible with this provider's profile.
     * <p>
     * This method checks key size and type. It does NOT verify key strength
     * or entropy (which must be ensured during key derivation).
     * </p>
     *
     * @param key the key to validate
     * @return true if the key is valid for this provider
     */
    default boolean isValidKey(SecretKey key) {
        if (key == null) {
            return false;
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            return false;
        }
        boolean valid = getProfile().isValidKeySize(encoded);
        // Zeroize temporary copy
        java.util.Arrays.fill(encoded, (byte) 0);
        return valid;
    }
}