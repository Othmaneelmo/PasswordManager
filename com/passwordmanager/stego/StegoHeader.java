package com.passwordmanager.stego;

import com.passwordmanager.crypto.SecurityProfile;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Header format for steganographically embedded data.
 * <p>
 * <b>Binary Format:</b>
 * </p>
 * <pre>
 * [Magic: 4 bytes] "STEG"
 * [Version: 1 byte] 0x01
 * [Profile: 1 byte] 0x00=FAST, 0x01=BALANCED, 0x02=PARANOID
 * [Payload Size: 4 bytes] big-endian uint32
 * [Filename Length: 2 bytes] big-endian uint16
 * [Filename: variable] UTF-8 encoded filename
 * [Reserved: 2 bytes] for future use (padding)
 * </pre>
 * <p>
 * Total header size: 14 + filename length bytes
 * </p>
 * 
 * <p><b>Design Rationale:</b></p>
 * <ul>
 *   <li>Magic bytes identify steganographic content</li>
 *   <li>Version allows format evolution</li>
 *   <li>Profile needed for correct decryption</li>
 *   <li>Payload size enables exact extraction</li>
 *   <li>Filename preserves original file identity</li>
 * </ul>
 */
public final class StegoHeader {
    private static final byte[] MAGIC = "STEG".getBytes(StandardCharsets.US_ASCII);
    private static final byte VERSION = 0x01;
    private static final int FIXED_HEADER_SIZE = 14;
    private static final int MAX_FILENAME_LENGTH = 255;
    private static final int MAX_PAYLOAD_SIZE = 100 * 1024 * 1024; // 100 MB limit
    
    private final SecurityProfile profile;
    private final int payloadSize;
    private final String originalFilename;
    
    /**
     * Constructs a steganography header.
     *
     * @param profile the security profile used for encryption
     * @param payloadSize the size of the encrypted payload in bytes
     * @param originalFilename the original filename (for reconstruction)
     * @throws IllegalArgumentException if parameters are invalid
     */
    public StegoHeader(SecurityProfile profile, int payloadSize, String originalFilename) {
        if (profile == null) {
            throw new IllegalArgumentException("Security profile cannot be null");
        }
        if (payloadSize < 0 || payloadSize > MAX_PAYLOAD_SIZE) {
            throw new IllegalArgumentException(
                "Payload size out of range: " + payloadSize + 
                " (max: " + MAX_PAYLOAD_SIZE + ")"
            );
        }
        if (originalFilename == null || originalFilename.isEmpty()) {
            throw new IllegalArgumentException("Original filename cannot be null or empty");
        }
        if (originalFilename.length() > MAX_FILENAME_LENGTH) {
            throw new IllegalArgumentException(
                "Filename too long: " + originalFilename.length() + 
                " (max: " + MAX_FILENAME_LENGTH + ")"
            );
        }
        
        this.profile = profile;
        this.payloadSize = payloadSize;
        this.originalFilename = originalFilename;
    }
    
    /**
     * Serializes this header to bytes.
     *
     * @return byte array containing the serialized header
     */
    public byte[] toBytes() {
        byte[] filenameBytes = originalFilename.getBytes(StandardCharsets.UTF_8);
        
        ByteBuffer buffer = ByteBuffer.allocate(FIXED_HEADER_SIZE + filenameBytes.length);
        
        // Magic
        buffer.put(MAGIC);
        
        // Version
        buffer.put(VERSION);
        
        // Profile
        buffer.put(profileToByte(profile));
        
        // Payload size
        buffer.putInt(payloadSize);
        
        // Filename length
        buffer.putShort((short) filenameBytes.length);
        
        // Filename
        buffer.put(filenameBytes);
        
        // Reserved bytes
        buffer.putShort((short) 0);
        
        return buffer.array();
    }
    
    /**
     * Deserializes a header from bytes.
     *
     * @param bytes the byte array to parse
     * @return the parsed StegoHeader
     * @throws IOException if the header is invalid or corrupted
     */
    public static StegoHeader fromBytes(byte[] bytes) throws IOException {
        if (bytes == null || bytes.length < FIXED_HEADER_SIZE) {
            throw new IOException("Header too short: expected at least " + FIXED_HEADER_SIZE + " bytes");
        }
        
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        
        // Validate magic
        byte[] magic = new byte[MAGIC.length];
        buffer.get(magic);
        if (!Arrays.equals(magic, MAGIC)) {
            throw new IOException("Invalid magic bytes - not a steganographic image");
        }
        
        // Validate version
        byte version = buffer.get();
        if (version != VERSION) {
            throw new IOException(
                "Unsupported version: " + version + " (expected: " + VERSION + ")"
            );
        }
        
        // Parse profile
        byte profileByte = buffer.get();
        SecurityProfile profile = byteToProfile(profileByte);
        
        // Parse payload size
        int payloadSize = buffer.getInt();
        if (payloadSize < 0 || payloadSize > MAX_PAYLOAD_SIZE) {
            throw new IOException("Invalid payload size: " + payloadSize);
        }
        
        // Parse filename length
        short filenameLength = buffer.getShort();
        if (filenameLength < 0 || filenameLength > MAX_FILENAME_LENGTH) {
            throw new IOException("Invalid filename length: " + filenameLength);
        }
        
        // Ensure we have enough bytes for filename
        if (buffer.remaining() < filenameLength + 2) { // +2 for reserved bytes
            throw new IOException("Header truncated: not enough bytes for filename");
        }
        
        // Parse filename
        byte[] filenameBytes = new byte[filenameLength];
        buffer.get(filenameBytes);
        String filename = new String(filenameBytes, StandardCharsets.UTF_8);
        
        // Skip reserved bytes
        buffer.getShort();
        
        return new StegoHeader(profile, payloadSize, filename);
    }
    
    /**
     * Returns the total size of this header in bytes.
     *
     * @return header size including filename
     */
    public int getSize() {
        return FIXED_HEADER_SIZE + originalFilename.getBytes(StandardCharsets.UTF_8).length;
    }
    
    /**
     * Returns the security profile.
     */
    public SecurityProfile getProfile() {
        return profile;
    }
    
    /**
     * Returns the payload size in bytes.
     */
    public int getPayloadSize() {
        return payloadSize;
    }
    
    /**
     * Returns the original filename.
     */
    public String getOriginalFilename() {
        return originalFilename;
    }
    
    /**
     * Converts SecurityProfile to byte representation.
     */
    private static byte profileToByte(SecurityProfile profile) {
        switch (profile) {
            case FAST: return 0x00;
            case BALANCED: return 0x01;
            case PARANOID: return 0x02;
            default: throw new IllegalArgumentException("Unknown profile: " + profile);
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
            default: throw new IOException("Unknown security profile byte: 0x" + 
                    String.format("%02X", b));
        }
    }
    
    @Override
    public String toString() {
        return String.format(
            "StegoHeader[profile=%s, payloadSize=%d, filename=%s]",
            profile.name(),
            payloadSize,
            originalFilename
        );
    }
}