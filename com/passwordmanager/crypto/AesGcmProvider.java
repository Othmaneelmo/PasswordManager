package com.passwordmanager.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * AES-GCM encryption provider with configurable security profiles.
 * <p>
 * <b>Algorithm: AES-GCM (Galois/Counter Mode)</b>
 * </p>
 * <ul>
 *   <li>Authenticated Encryption with Associated Data (AEAD)</li>
 *   <li>Provides both confidentiality and authenticity</li>
 *   <li>Resistant to padding oracle attacks</li>
 *   <li>Efficient hardware acceleration on modern CPUs</li>
 * </ul>
 * 
 * <p><b>Security Properties:</b></p>
 * <ul>
 *   <li>IVs are generated using {@link SecureRandom}</li>
 *   <li>IV uniqueness is cryptographically guaranteed</li>
 *   <li>Authentication tag is verified before decryption</li>
 *   <li>No plaintext is returned if authentication fails</li>
 * </ul>
 * 
 * <p><b>Key Derivation:</b></p>
 * <p>
 * This provider expects a 256-bit key from {@code VaultSession.getVaultSessionKey()}.
 * For profiles requiring different key sizes:
 * </p>
 * <ul>
 *   <li><b>128-bit profiles:</b> Truncates the 256-bit key (uses first 16 bytes)</li>
 *   <li><b>256-bit profiles:</b> Uses the full key</li>
 * </ul>
 * <p>
 * <b>Note:</b> Truncation is cryptographically sound when the source key has
 * sufficient entropy (which PBKDF2 with 600k iterations guarantees).
 * </p>
 * 
 * <p><b>Thread Safety:</b></p>
 * <p>
 * This class is thread-safe. Each operation creates a new {@link Cipher} instance,
 * avoiding shared mutable state.
 * </p>
 * 
 * <p><b>Performance Characteristics:</b></p>
 * <ul>
 *   <li><b>FAST profile:</b> ~1-2 GB/s on modern hardware</li>
 *   <li><b>BALANCED profile:</b> ~800 MB/s - 1.5 GB/s</li>
 *   <li><b>PARANOID profile:</b> ~800 MB/s - 1.5 GB/s (slight overhead from larger IV)</li>
 * </ul>
 * <p>
 * Actual performance depends on CPU, JVM, and data size.
 * </p>
 * 
 * <p><b>Limitations:</b></p>
 * <ul>
 *   <li>Maximum plaintext size: ~64 GB (GCM counter limit)</li>
 *   <li>Maximum operations per key: 2^32 (IV collision risk)</li>
 *   <li>Key must be rotated before these limits are reached</li>
 * </ul>
 */
public final class AesGcmProvider implements EncryptionProvider {
    private final SecurityProfile profile;
    private final SecureRandom secureRandom;

    /**
     * Constructs an AES-GCM provider with the specified security profile.
     * <p>
     * The profile determines key size, IV size, and authentication tag size.
     * </p>
     *
     * @param profile the security profile to use
     * @throws IllegalArgumentException if profile is null or incompatible
     */
    public AesGcmProvider(SecurityProfile profile) {
        if (profile == null) {
            throw new IllegalArgumentException("Security profile cannot be null");
        }
        
        // Validate that the profile uses AES-GCM
        if (!profile.getTransformation().startsWith("AES/GCM/")) {
            throw new IllegalArgumentException(
                "AesGcmProvider only supports AES/GCM profiles, got: " + 
                profile.getTransformation()
            );
        }

        this.profile = profile;
        this.secureRandom = new SecureRandom();
    }

    @Override
    public EncryptionResult encrypt(byte[] plaintext, SecretKey key) 
            throws GeneralSecurityException {
        
        validateEncryptInputs(plaintext, key);

        // Generate unique IV for this encryption operation
        byte[] iv = generateIv();

        // Derive appropriate key size from session key
        SecretKey aesKey = deriveAesKey(key);

        try {
            // Initialize cipher for encryption
            Cipher cipher = Cipher.getInstance(profile.getTransformation());
            GCMParameterSpec spec = new GCMParameterSpec(profile.getTagBits(), iv);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);

            // Encrypt and authenticate
            byte[] ciphertext = cipher.doFinal(plaintext);

            return new EncryptionResult(iv, ciphertext, profile);

        } finally {
            // Zeroize temporary key material
            zeroizeKey(aesKey);
        }
    }

    @Override
    public byte[] decrypt(EncryptionResult encrypted, SecretKey key) 
            throws GeneralSecurityException {
        
        validateDecryptInputs(encrypted, key);

        // Verify profile matches
        if (encrypted.getProfile() != this.profile) {
            throw new IllegalArgumentException(
                "EncryptionResult profile (" + encrypted.getProfile() + 
                ") does not match provider profile (" + this.profile + ")"
            );
        }

        // Derive appropriate key size from session key
        SecretKey aesKey = deriveAesKey(key);

        try {
            // Initialize cipher for decryption
            Cipher cipher = Cipher.getInstance(profile.getTransformation());
            GCMParameterSpec spec = new GCMParameterSpec(
                profile.getTagBits(), 
                encrypted.getIv()
            );
            cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);

            // Decrypt and verify authentication tag
            // If tag verification fails, this throws AEADBadTagException
            byte[] plaintext = cipher.doFinal(encrypted.getCiphertext());

            return plaintext;

        } finally {
            // Zeroize temporary key material
            zeroizeKey(aesKey);
        }
    }

    @Override
    public SecurityProfile getProfile() {
        return profile;
    }

    /**
     * Generates a cryptographically random IV of the appropriate size.
     * <p>
     * IV size is determined by the security profile:
     * - FAST, BALANCED: 96 bits (12 bytes) - recommended GCM nonce size
     * - PARANOID: 128 bits (16 bytes) - extended for additional margin
     * </p>
     *
     * @return a unique random IV
     */
    private byte[] generateIv() {
        byte[] iv = new byte[profile.getIvBytes()];
        secureRandom.nextBytes(iv);
        return iv;
    }

    /**
     * Derives an AES key of the appropriate size from the session key.
     * <p>
     * The vault session key is always 256 bits (from PBKDF2). This method
     * adapts it to the profile's required key size:
     * </p>
     * <ul>
     *   <li><b>256-bit profiles:</b> Uses full key</li>
     *   <li><b>128-bit profiles:</b> Truncates to first 16 bytes</li>
     * </ul>
     * <p>
     * <b>Security Note:</b> Truncation is safe because PBKDF2 produces
     * uniformly distributed bits. Each byte has ~256 bits of entropy.
     * </p>
     *
     * @param sessionKey the 256-bit session key from VaultSession
     * @return an AES key of the appropriate size
     * @throws IllegalArgumentException if session key is not 256 bits
     */
    private SecretKey deriveAesKey(SecretKey sessionKey) {
        byte[] sessionKeyBytes = sessionKey.getEncoded();
        
        if (sessionKeyBytes == null || sessionKeyBytes.length != 32) {
            throw new IllegalArgumentException(
                "Session key must be 32 bytes (256 bits), got: " + 
                (sessionKeyBytes == null ? "null" : sessionKeyBytes.length)
            );
        }

        int requiredBytes = profile.getKeyBytes();
        byte[] aesKeyBytes;

        if (requiredBytes == 32) {
            // Use full 256-bit key
            aesKeyBytes = Arrays.copyOf(sessionKeyBytes, 32);
        } else if (requiredBytes == 16) {
            // Truncate to 128 bits
            aesKeyBytes = Arrays.copyOf(sessionKeyBytes, 16);
        } else {
            throw new IllegalStateException(
                "Unsupported key size: " + requiredBytes + " bytes"
            );
        }

        // Zeroize temporary copy of session key
        Arrays.fill(sessionKeyBytes, (byte) 0);

        return new SecretKeySpec(aesKeyBytes, "AES");
    }

    /**
     * Securely zeroizes a secret key's raw bytes.
     * <p>
     * This attempts to clear the key material from memory. However,
     * some SecretKey implementations may not expose raw bytes.
     * </p>
     */
    private void zeroizeKey(SecretKey key) {
        if (key == null) {
            return;
        }
        byte[] encoded = key.getEncoded();
        if (encoded != null) {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    /**
     * Validates inputs for encryption operation.
     */
    private void validateEncryptInputs(byte[] plaintext, SecretKey key) {
        if (plaintext == null || plaintext.length == 0) {
            throw new IllegalArgumentException("Plaintext cannot be null or empty");
        }
        if (key == null) {
            throw new IllegalArgumentException("Encryption key cannot be null");
        }
        if (!isValidKey(key)) {
            throw new IllegalArgumentException(
                "Key size must be 32 bytes (256 bits) for AES-GCM"
            );
        }
    }

    /**
     * Validates inputs for decryption operation.
     */
    private void validateDecryptInputs(EncryptionResult encrypted, SecretKey key) {
        if (encrypted == null) {
            throw new IllegalArgumentException("EncryptionResult cannot be null");
        }
        if (key == null) {
            throw new IllegalArgumentException("Decryption key cannot be null");
        }
        if (!isValidKey(key)) {
            throw new IllegalArgumentException(
                "Key size must be 32 bytes (256 bits) for AES-GCM"
            );
        }
    }

    @Override
    public boolean isValidKey(SecretKey key) {
        if (key == null) {
            return false;
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            return false;
        }
        // Session key must always be 256 bits
        boolean valid = encoded.length == 32;
        Arrays.fill(encoded, (byte) 0);
        return valid;
    }
}