package com.passwordmanager.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Defines the encrypted file format specification.
 * <p>
 * <b>File Structure:</b>
 * </p>
 * <pre>
 * [Magic Header: 8 bytes] "VAULTENC"
 * [Format Version: 1 byte] 0x01
 * [Security Profile: 1 byte] 0x00=FAST, 0x01=BALANCED, 0x02=PARANOID
 * [IV Length: 2 bytes] big-endian uint16
 * [IV: variable] initialization vector
 * [Ciphertext + Tag: variable] encrypted data with embedded auth tag
 * </pre>
 * 
 * <p><b>Security Properties:</b></p>
 * <ul>
 *   <li>Self-describing - all metadata included for decryption</li>
 *   <li>Version-tagged - supports future format changes</li>
 *   <li>Tamper-evident - authenticated encryption detects modifications</li>
 *   <li>Algorithm-agnostic - profile byte maps to crypto parameters</li>
 * </ul>
 * 
 * <p><b>Future Extensibility:</b></p>
 * <ul>
 *   <li>Version byte allows format evolution</li>
 *   <li>Can add compression flag, key rotation metadata</li>
 *   <li>Can embed steganographic markers</li>
 *   <li>Can add file integrity manifests</li>
 * </ul>
 */
public class EncryptedFileFormat {

    // Magic header to identify encrypted files
    private static final byte[] MAGIC_HEADER = "VAULTENC".getBytes(StandardCharsets.US_ASCII);
    
    // Current format version
    private static final byte FORMAT_VERSION = 0x01;
    
    // Header size: magic(8) + version(1) + profile(1) + ivLen(2) = 12 bytes
    private static final int HEADER_SIZE = 12;
    
    // Maximum IV size (supports up to 64KB IVs for future algorithms)
    private static final int MAX_IV_LENGTH = 65535;
    
    private EncryptedFileFormat() {
        throw new AssertionError("Utility class");
    }
    
    /**
     * Metadata extracted from encrypted file header.
    */
    public static final class FileMetadata {
        private final byte version;
        private final SecurityProfile profile;
        private final byte[] iv;
        
        public FileMetadata(byte version, SecurityProfile profile, byte[] iv) {
            this.version = version;
            this.profile = profile;
            this.iv = iv;
        }
        
        public byte getVersion() {
            return version;
        }
        
        public SecurityProfile getProfile() {
            return profile;
        }
        
        public byte[] getIv() {
            return iv;
        }
        
        public void zeroize() {
            Arrays.fill(iv, (byte) 0);
        }
    }
    
}
