package com.passwordmanager.crypto;

import java.util.Arrays;

/**
 * Immutable container for encrypted data with associated metadata.
 * <p>
 * Contains all information necessary to decrypt the data:
 * </p>
 * <ul>
 *   <li><b>iv</b> - Initialization vector / nonce used for encryption</li>
 *   <li><b>ciphertext</b> - Encrypted data (includes authentication tag for AEAD modes)</li>
 *   <li><b>profile</b> - Security profile used (for verification and decryption)</li>
 * </ul>
 * 
 * <p><b>Security Guarantees:</b></p>
 * <ul>
 *   <li>IV is unique per encryption operation</li>
 *   <li>Ciphertext includes authentication tag (AEAD)</li>
 *   <li>Profile ensures correct decryption parameters</li>
 *   <li>Immutable - cannot be modified after creation</li>
 * </ul>
 * 
 * <p><b>Memory Safety:</b></p>
 * <p>
 * This class stores byte arrays. Callers should zeroize sensitive plaintext
 * after encryption. The ciphertext itself is safe to persist (it's encrypted).
 * </p>
 * 
 * <p><b>Serialization:</b></p>
 * <p>
 * This class can be serialized for storage. Recommended format:
 * <pre>
 * [1 byte: profile ordinal][2 bytes: IV length][IV bytes][ciphertext bytes]
 * </pre>
 * Future commits will add serialization methods.
 * </p>
 */
public final class EncryptionResult {
    private final byte[] iv;
    private final byte[] ciphertext;
    private final SecurityProfile profile;

    /**
     * Constructs an encryption result with the given parameters.
     * <p>
     * <b>Important:</b> This constructor does NOT copy the arrays. The caller
     * must not modify the arrays after passing them to this constructor.
     * </p>
     *
     * @param iv the initialization vector used for encryption
     * @param ciphertext the encrypted data (including authentication tag)
     * @param profile the security profile used for encryption
     * @throws IllegalArgumentException if any parameter is null
     */
    public EncryptionResult(byte[] iv, byte[] ciphertext, SecurityProfile profile) {
        if (iv == null) {
            throw new IllegalArgumentException("IV cannot be null");
        }
        if (ciphertext == null) {
            throw new IllegalArgumentException("Ciphertext cannot be null");
        }
        if (profile == null) {
            throw new IllegalArgumentException("Security profile cannot be null");
        }

        this.iv = iv;
        this.ciphertext = ciphertext;
        this.profile = profile;
    }

    /**
     * Returns the initialization vector used for encryption.
     * <p>
     * <b>Warning:</b> The returned array is NOT a copy. Do not modify it.
     * Future versions may return defensive copies.
     * </p>
     *
     * @return the IV bytes
     */
    public byte[] getIv() {
        return iv;
    }

    /**
     * Returns the encrypted data including authentication tag.
     * <p>
     * For AEAD modes like GCM, the authentication tag is appended to the ciphertext.
     * </p>
     *
     * @return the ciphertext bytes
     */
    public byte[] getCiphertext() {
        return ciphertext;
    }

    /**
     * Returns the security profile used for this encryption.
     * <p>
     * The same profile must be used for decryption.
     * </p>
     *
     * @return the security profile
     */
    public SecurityProfile getProfile() {
        return profile;
    }

    /**
     * Returns the total size of encrypted data in bytes.
     * <p>
     * This includes the authentication tag but excludes the IV
     * (which is transmitted separately).
     * </p>
     *
     * @return ciphertext length in bytes
     */
    public int getCiphertextSize() {
        return ciphertext.length;
    }

    /**
     * Returns the total overhead in bytes for this encryption.
     * <p>
     * Overhead = IV size + tag size (embedded in ciphertext)
     * </p>
     *
     * @return total overhead in bytes
     */
    public int getOverheadBytes() {
        return iv.length + (profile.getTagBits() / 8);
    }

    /**
     * Securely zeroizes all sensitive data in this result.
     * <p>
     * <b>Note:</b> Ciphertext is encrypted and generally safe to leave in memory,
     * but this method zeroizes everything for defense-in-depth.
     * </p>
     * <p>
     * After calling this method, the EncryptionResult should not be used.
     * </p>
     */
    public void zeroize() {
        Arrays.fill(iv, (byte) 0);
        Arrays.fill(ciphertext, (byte) 0);
    }

    @Override
    public String toString() {
        return String.format(
            "EncryptionResult[profile=%s, ivSize=%d, ciphertextSize=%d]",
            profile.name(),
            iv.length,
            ciphertext.length
        );
    }
}