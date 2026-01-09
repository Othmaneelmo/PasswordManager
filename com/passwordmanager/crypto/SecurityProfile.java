package com.passwordmanager.crypto;

/**
 * Defines a cryptographic security profile with specific algorithm parameters.
 * <p>
 * Each profile represents a distinct security/performance tradeoff:
 * </p>
 * <ul>
 *   <li><b>FAST</b> - Optimized for speed, suitable for non-critical data</li>
 *   <li><b>BALANCED</b> - Recommended default for most use cases</li>
 *   <li><b>PARANOID</b> - Maximum security, regardless of performance cost</li>
 * </ul>
 * 
 * <p><b>Design Rationale:</b></p>
 * <ul>
 *   <li>Immutable - profiles are constants, preventing runtime tampering</li>
 *   <li>Explicit - all cryptographic parameters are visible and auditable</li>
 *   <li>Extensible - new profiles can be added without breaking existing code</li>
 * </ul>
 * 
 * <p><b>Future Expansion:</b></p>
 * <p>
 * Additional profiles could include:
 * - COMPLIANCE (meets specific regulatory requirements like FIPS 140-2)
 * - QUANTUM_RESISTANT (uses post-quantum algorithms)
 * - STEALTH (optimized for steganographic use cases)
 * </p>
 */
public enum SecurityProfile {
    /**
     * Fast profile prioritizing performance over maximum security.
     * <p>
     * <b>Cryptographic Parameters:</b>
     * </p>
     * <ul>
     *   <li>Algorithm: AES-GCM</li>
     *   <li>Key size: 128 bits</li>
     *   <li>IV size: 96 bits (recommended GCM nonce size)</li>
     *   <li>Tag size: 96 bits</li>
     * </ul>
     * <p>
     * <b>Use Cases:</b> Temporary data, caching, non-critical storage
     * </p>
     */
    FAST(
        "AES/GCM/NoPadding",
        128,  // key bits
        96,   // IV bits
        96    // tag bits
    ),

    /**
     * Balanced profile offering strong security with good performance.
     * <p>
     * <b>Cryptographic Parameters:</b>
     * </p>
     * <ul>
     *   <li>Algorithm: AES-GCM</li>
     *   <li>Key size: 256 bits</li>
     *   <li>IV size: 96 bits</li>
     *   <li>Tag size: 128 bits (full authentication strength)</li>
     * </ul>
     * <p>
     * <b>Use Cases:</b> Default for password entries, secure notes, most data
     * </p>
     */
    BALANCED(
        "AES/GCM/NoPadding",
        256,  // key bits
        96,   // IV bits
        128   // tag bits
    ),

    /**
     * Paranoid profile maximizing security regardless of performance.
     * <p>
     * <b>Cryptographic Parameters:</b>
     * </p>
     * <ul>
     *   <li>Algorithm: AES-GCM</li>
     *   <li>Key size: 256 bits</li>
     *   <li>IV size: 128 bits (extended nonce for additional security margin)</li>
     *   <li>Tag size: 128 bits</li>
     * </ul>
     * <p>
     * <b>Security Notes:</b>
     * </p>
     * <ul>
     *   <li>Longer IV reduces collision probability in high-volume scenarios</li>
     *   <li>Suitable for long-term archival or highly sensitive data</li>
     *   <li>May have slightly reduced performance due to larger overhead</li>
     * </ul>
     * <p>
     * <b>Use Cases:</b> Master secrets, recovery keys, highly sensitive credentials
     * </p>
     */
    PARANOID(
        "AES/GCM/NoPadding",
        256,  // key bits
        128,  // IV bits (larger for extra margin)
        128   // tag bits
    );

    private final String transformation;
    private final int keyBits;
    private final int ivBits;
    private final int tagBits;

    SecurityProfile(String transformation, int keyBits, int ivBits, int tagBits) {
        this.transformation = transformation;
        this.keyBits = keyBits;
        this.ivBits = ivBits;
        this.tagBits = tagBits;
    }

    /**
     * Returns the JCE transformation string for this profile.
     * <p>
     * Format: "Algorithm/Mode/Padding"
     * </p>
     *
     * @return the transformation string (e.g., "AES/GCM/NoPadding")
     */
    public String getTransformation() {
        return transformation;
    }

    /**
     * Returns the key size in bits for this profile.
     *
     * @return key size (128 or 256 bits)
     */
    public int getKeyBits() {
        return keyBits;
    }

    /**
     * Returns the key size in bytes for this profile.
     *
     * @return key size in bytes (16 or 32 bytes)
     */
    public int getKeyBytes() {
        return keyBits / 8;
    }

    /**
     * Returns the IV/nonce size in bits for this profile.
     *
     * @return IV size (96 or 128 bits)
     */
    public int getIvBits() {
        return ivBits;
    }

    /**
     * Returns the IV/nonce size in bytes for this profile.
     *
     * @return IV size in bytes (12 or 16 bytes)
     */
    public int getIvBytes() {
        return ivBits / 8;
    }

    /**
     * Returns the authentication tag size in bits for this profile.
     *
     * @return tag size (96 or 128 bits)
     */
    public int getTagBits() {
        return tagBits;
    }

    /**
     * Returns a human-readable description of this profile's security characteristics.
     *
     * @return security profile description
     */
    public String getDescription() {
        return String.format(
            "%s: %s with %d-bit key, %d-bit IV, %d-bit tag",
            name(),
            transformation,
            keyBits,
            ivBits,
            tagBits
        );
    }

    /**
     * Validates that a given key is compatible with this profile.
     * <p>
     * For profiles requiring larger keys than the session key provides,
     * key derivation or rejection is required.
     * </p>
     *
     * @param keyBytes the key to validate
     * @return true if the key size matches this profile's requirements
     */
    public boolean isValidKeySize(byte[] keyBytes) {
        return keyBytes != null && keyBytes.length == getKeyBytes();
    }
}