package com.passwordmanager.stego;

import java.io.IOException;

/**
 * LSB (Least Significant Bit) steganography implementation.
 * <p>
 * <b>Algorithm:</b>
 * </p>
 * <pre>
 * Embedding:
 * 1. Traverse pixels left-to-right, top-to-bottom
 * 2. For each pixel, extract RGB channels
 * 3. Replace LSB of R, G, B with 3 bits from payload
 * 4. Continue until all payload bits embedded
 * 
 * Extraction:
 * 1. Traverse pixels in same order
 * 2. Extract LSB from R, G, B channels
 * 3. Accumulate bits into bytes
 * 4. Continue until payload size reached
 * </pre>
 * 
 * <p><b>Example:</b></p>
 * <pre>
 * Original pixel: RGB(10110010, 11001101, 01010111)
 * Payload bits:   101
 * 
 * Modified pixel: RGB(10110011, 11001100, 01010111)
 *                     ^^^^^^^-   ^^^^^^^-   ^^^^^^^- (LSB changed)
 * 
 * Visual change: Imperceptible (±1 per channel)
 * </pre>
 * 
 * <p><b>Security Properties:</b></p>
 * <ul>
 *   <li>LSB changes are imperceptible to human eye</li>
 *   <li>Statistical analysis can detect presence but not content</li>
 *   <li>Encryption ensures payload is random-looking data</li>
 *   <li>No information about payload in pixel patterns</li>
 * </ul>
 */
public final class LSBSteganography {
    
    private LSBSteganography() {
        throw new AssertionError("Utility class");
    }
    
    /**
     * Embeds data into a carrier image using LSB steganography.
     * <p>
     * <b>Process:</b>
     * </p>
     * <ol>
     *   <li>Validate carrier capacity</li>
     *   <li>Convert data to bit stream</li>
     *   <li>Embed bits into pixel LSBs</li>
     *   <li>Return modified carrier</li>
     * </ol>
     *
     * @param carrier the carrier image
     * @param data the data to embed (should be encrypted)
     * @return the modified carrier with embedded data
     * @throws IllegalArgumentException if data is too large
     */
    public static ImageCarrier embed(ImageCarrier carrier, byte[] data) {
        if (carrier == null) {
            throw new IllegalArgumentException("Carrier cannot be null");
        }
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data cannot be null or empty");
        }
        
        // Validate capacity
        carrier.validateCapacity(data.length);
        
        int width = carrier.getWidth();
        int height = carrier.getHeight();
        
        // Track bit position in data
        int byteIndex = 0;
        int bitIndex = 0;
        
        // Traverse pixels
        outerLoop:
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                // Check if we've embedded all data
                if (byteIndex >= data.length) {
                    break outerLoop;
                }
                
                // Get current pixel RGB
                int rgb = carrier.getRGB(x, y);
                
                // Extract RGB channels
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;
                
                // Embed 3 bits (one per channel)
                // R channel
                if (byteIndex < data.length) {
                    int bit = (data[byteIndex] >> (7 - bitIndex)) & 1;
                    r = (r & 0xFE) | bit; // Clear LSB and set to bit value
                    
                    bitIndex++;
                    if (bitIndex == 8) {
                        bitIndex = 0;
                        byteIndex++;
                    }
                }
                
                // G channel
                if (byteIndex < data.length) {
                    int bit = (data[byteIndex] >> (7 - bitIndex)) & 1;
                    g = (g & 0xFE) | bit;
                    
                    bitIndex++;
                    if (bitIndex == 8) {
                        bitIndex = 0;
                        byteIndex++;
                    }
                }
                
                // B channel
                if (byteIndex < data.length) {
                    int bit = (data[byteIndex] >> (7 - bitIndex)) & 1;
                    b = (b & 0xFE) | bit;
                    
                    bitIndex++;
                    if (bitIndex == 8) {
                        bitIndex = 0;
                        byteIndex++;
                    }
                }
                
                // Reconstruct and set modified pixel
                int modifiedRGB = (r << 16) | (g << 8) | b;
                carrier.setRGB(x, y, modifiedRGB);
            }
        }
        
        return carrier;
    }
    
    /**
     * Extracts data from a carrier image using LSB steganography.
     * <p>
     * <b>Process:</b>
     * </p>
     * <ol>
     *   <li>Traverse pixels in same order as embedding</li>
     *   <li>Extract LSB from each RGB channel</li>
     *   <li>Accumulate bits into bytes</li>
     *   <li>Return extracted data</li>
     * </ol>
     *
     * @param carrier the carrier image containing embedded data
     * @param dataLength the number of bytes to extract
     * @return the extracted data
     * @throws IOException if extraction fails
     */
    public static byte[] extract(ImageCarrier carrier, int dataLength) throws IOException {
        if (carrier == null) {
            throw new IllegalArgumentException("Carrier cannot be null");
        }
        if (dataLength < 0) {
            throw new IllegalArgumentException("Data length cannot be negative");
        }
        if (dataLength > carrier.getCapacityBytes()) {
            throw new IOException(
                "Requested data length exceeds carrier capacity: " + 
                dataLength + " > " + carrier.getCapacityBytes()
            );
        }
        
        byte[] data = new byte[dataLength];
        int width = carrier.getWidth();
        int height = carrier.getHeight();
        
        // Track position in output data
        int byteIndex = 0;
        int bitIndex = 0;
        int currentByte = 0;
        
        // Traverse pixels
        outerLoop:
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                // Check if we've extracted all data
                if (byteIndex >= dataLength) {
                    break outerLoop;
                }
                
                // Get current pixel RGB
                int rgb = carrier.getRGB(x, y);
                
                // Extract RGB channels
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;
                
                // Extract 3 bits (one per channel)
                // R channel LSB
                int bit = r & 1;
                currentByte = (currentByte << 1) | bit;
                bitIndex++;
                
                if (bitIndex == 8) {
                    data[byteIndex++] = (byte) currentByte;
                    currentByte = 0;
                    bitIndex = 0;
                    
                    if (byteIndex >= dataLength) {
                        break outerLoop;
                    }
                }
                
                // G channel LSB
                bit = g & 1;
                currentByte = (currentByte << 1) | bit;
                bitIndex++;
                
                if (bitIndex == 8) {
                    data[byteIndex++] = (byte) currentByte;
                    currentByte = 0;
                    bitIndex = 0;
                    
                    if (byteIndex >= dataLength) {
                        break outerLoop;
                    }
                }
                
                // B channel LSB
                bit = b & 1;
                currentByte = (currentByte << 1) | bit;
                bitIndex++;
                
                if (bitIndex == 8) {
                    data[byteIndex++] = (byte) currentByte;
                    currentByte = 0;
                    bitIndex = 0;
                    
                    if (byteIndex >= dataLength) {
                        break outerLoop;
                    }
                }
            }
        }
        
        return data;
    }
    
    /**
     * Calculates the required carrier size for a given payload.
     *
     * @param payloadSize the payload size in bytes
     * @return required number of pixels (width × height)
     */
    public static long calculateRequiredPixels(int payloadSize) {
        // Each pixel stores 3 bits, need 8 bits per byte
        long bitsNeeded = (long) payloadSize * 8;
        long pixelsNeeded = (bitsNeeded + 2) / 3; // Round up
        return pixelsNeeded;
    }
    
    /**
     * Suggests minimum image dimensions for a payload.
     *
     * @param payloadSize the payload size in bytes
     * @return a string describing minimum dimensions
     */
    public static String suggestImageSize(int payloadSize) {
        long pixels = calculateRequiredPixels(payloadSize);
        
        // Suggest square-ish dimensions
        int side = (int) Math.ceil(Math.sqrt(pixels));
        
        return String.format(
            "Minimum %dx%d pixels (total: %d pixels) for %d bytes",
            side,
            side,
            side * side,
            payloadSize
        );
    }
}