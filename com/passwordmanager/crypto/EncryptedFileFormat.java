package com.passwordmanager.crypto;

import java.io.*;
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
public final class EncryptedFileFormat {
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
            throw new IllegalArgumentException(
                "IV length exceeds maximum: " + iv.length + " > " + MAX_IV_LENGTH
            );
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
     * Reads and validates encrypted file header.
     * <p>
     * Performs strict validation:
     * - Magic header must match exactly
     * - Version must be supported
     * - Profile must be valid
     * - IV length must be reasonable
     * </p>
     *
     * @param in input stream positioned at start of file
     * @return metadata extracted from header
     * @throws IOException if read fails or format is invalid
     */
    public static FileMetadata readHeader(InputStream in) throws IOException {
        // Read and validate magic header
        byte[] magic = readExactly(in, MAGIC_HEADER.length);
        if (!Arrays.equals(magic, MAGIC_HEADER)) {
            throw new IOException(
                "Invalid file format - not an encrypted vault file (bad magic header)"
            );
        }
        
        // Read version
        int versionInt = in.read();
        if (versionInt == -1) {
            throw new IOException("Unexpected end of file reading version");
        }
        byte version = (byte) versionInt;
        
        if (version != FORMAT_VERSION) {
            throw new IOException(
                "Unsupported file format version: " + version + 
                " (expected: " + FORMAT_VERSION + ")"
            );
        }
        
        // Read profile
        int profileByte = in.read();
        if (profileByte == -1) {
            throw new IOException("Unexpected end of file reading profile");
        }
        SecurityProfile profile = byteToProfile((byte) profileByte);
        
        // Read IV length (big-endian uint16)
        int ivLenHigh = in.read();
        int ivLenLow = in.read();
        if (ivLenHigh == -1 || ivLenLow == -1) {
            throw new IOException("Unexpected end of file reading IV length");
        }
        int ivLen = ((ivLenHigh & 0xFF) << 8) | (ivLenLow & 0xFF);
        
        if (ivLen <= 0 || ivLen > MAX_IV_LENGTH) {
            throw new IOException("Invalid IV length: " + ivLen);
        }
        
        // Validate IV length matches profile expectations
        if (ivLen != profile.getIvBytes()) {
            throw new IOException(
                "IV length mismatch - file has " + ivLen + " bytes, " +
                "but profile " + profile + " expects " + profile.getIvBytes()
            );
        }
        
        // Read IV
        byte[] iv = readExactly(in, ivLen);
        
        return new FileMetadata(version, profile, iv);
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
     * Returns the expected header size for a given IV length.
     * <p>
     * Useful for validation and pre-allocation.
     * </p>
     *
     * @param ivLength length of IV in bytes
     * @return total header size in bytes
     */
    public static int getHeaderSize(int ivLength) {
        return HEADER_SIZE + ivLength;
    }
    
    /**
     * Validates that a file appears to be encrypted (has correct magic).
     * <p>
     * This is a lightweight check that doesn't parse the full header.
     * </p>
     *
     * @param file file to check
     * @return true if file starts with magic header
     */
    public static boolean isEncryptedFile(File file) {
        if (!file.exists() || !file.canRead()) {
            return false;
        }
        
        try (InputStream in = new BufferedInputStream(new FileInputStream(file))) {
            byte[] magic = new byte[MAGIC_HEADER.length];
            int read = in.read(magic);
            return read == MAGIC_HEADER.length && Arrays.equals(magic, MAGIC_HEADER);
        } catch (IOException e) {
            return false;
        }
    }
}