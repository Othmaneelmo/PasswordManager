package com.passwordmanager.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
    
    /**
     * Writes encrypted file header to output stream.
     * <p>
     * Format: [MAGIC][VERSION][PROFILE][IV_LEN][IV]
     * </p>
     *
     * @param out output stream
     * @param profile security profile used
     * @param iv initialization vector
     * @throws IOException if write fails
     * @throws IllegalArgumentException if IV is too large
     */
    public static void writeHeader(OutputStream out, SecurityProfile profile, byte[] iv) 
            throws IOException {
        
        if (iv == null || iv.length == 0) {
            throw new IllegalArgumentException("IV cannot be null or empty");
        }
        if (iv.length > MAX_IV_LENGTH) {
            throw new IllegalArgumentException("IV length exceeds maximum: " + iv.length + " > " + MAX_IV_LENGTH);
        }
       // Write magic header
        out.write(MAGIC_HEADER);
        
        // Write version
        out.write(FORMAT_VERSION);
        
        // Write profile byte
        out.write(profileToByte(profile));
        
        // Write IV length (big-endian uint16)
        int ivLen = iv.length;
        out.write((ivLen >> 8) & 0xFF);
        out.write(ivLen & 0xFF);
        
        // Write IV
        out.write(iv);
    }




    /**
     * Converts SecurityProfile to byte representation.
     */
    private static byte profileToByte(SecurityProfile profile) {
        switch (profile) {
            case FAST: return 0x00;
            case BALANCED: return 0x01;
            case PARANOID: return 0x02;
            default:
                throw new IllegalArgumentException("Unknown profile: " + profile);
        }
    }
    /**
     * Converts byte to SecurityProfile.
     */
    private static SecurityProfile byteToProfile(byte b) throws IOException {
        switch (b) {
            case 0x00: return SecurityProfile.FAST;
            case 0x01: return SecurityProfile.BALANCED;
            case 0x02: return SecurityProfile.PARANOID;
            default:
                throw new IOException("Unknown security profile byte: 0x" + 
                    String.format("%02X", b));
        }
    }

    /**
     * Reads exactly n bytes from input stream.
     * <p>
     * Unlike InputStream.read(), this method guarantees to read the full
     * amount or throw an exception.
     * </p>
     *
     * @param in input stream
     * @param n number of bytes to read
     * @return byte array of exactly n bytes
     * @throws IOException if fewer than n bytes available
     */
    private static byte[] readExactly(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n];
        int offset = 0;
        
        while (offset < n) {
            int read = in.read(buf, offset, n - offset);
            if (read == -1) {
                throw new IOException(
                    "Unexpected end of file - expected " + n + 
                    " bytes, got " + offset
                );
            }
            offset += read;
        }
        
        return buf;
    }
}
