package com.passwordmanager.stego;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import javax.imageio.ImageIO;

/**
 * Carrier image wrapper for steganographic operations.
 * <p>
 * This class:
 * - Loads and validates carrier images
 * - Calculates embedding capacity
 * - Provides pixel access for LSB manipulation
 * - Preserves image format integrity
 * </p>
 * 
 * <p><b>Supported Formats:</b></p>
 * <ul>
 *   <li>PNG - Lossless, preferred format</li>
 *   <li>BMP - Lossless, maximum capacity</li>
 * </ul>
 * 
 * <p><b>Capacity Calculation:</b></p>
 * <pre>
 * Capacity (bytes) = (width × height × 3) / 8
 *                  = total RGB channels / bits per byte
 * 
 * Example: 1920×1080 image
 *   = 1920 × 1080 × 3 / 8
 *   = 6,220,800 / 8
 *   = 777,600 bytes (~760 KB)
 * </pre>
 */
public final class ImageCarrier {
    private final BufferedImage image;
    private final int width;
    private final int height;
    private final long capacityBytes;
    private final String format;
    
    /**
     * Loads an image carrier from file.
     *
     * @param imageFile the image file to load
     * @throws IOException if the image cannot be loaded
     * @throws IllegalArgumentException if the image format is unsupported
     */
    public ImageCarrier(File imageFile) throws IOException {
        if (imageFile == null || !imageFile.exists()) {
            throw new IllegalArgumentException("Image file does not exist");
        }
        
        // Determine format from extension
        String filename = imageFile.getName().toLowerCase();
        if (filename.endsWith(".png")) {
            this.format = "PNG";
        } else if (filename.endsWith(".bmp")) {
            this.format = "BMP";
        } else {
            throw new IllegalArgumentException(
                "Unsupported image format. Only PNG and BMP are supported."
            );
        }
        
        // Load image
        this.image = ImageIO.read(imageFile);
        if (this.image == null) {
            throw new IOException("Failed to load image - file may be corrupted");
        }
        
        // Convert to RGB if needed (some images might be grayscale or indexed)
        if (this.image.getType() != BufferedImage.TYPE_INT_RGB && 
            this.image.getType() != BufferedImage.TYPE_INT_ARGB) {
            
            BufferedImage rgb = new BufferedImage(
                this.image.getWidth(),
                this.image.getHeight(),
                BufferedImage.TYPE_INT_RGB
            );
            rgb.getGraphics().drawImage(this.image, 0, 0, null);
            this.image.getGraphics().dispose();
            // Update reference
            BufferedImage temp = this.image;
        }
        
        this.width = image.getWidth();
        this.height = image.getHeight();
        
        // Calculate capacity: 3 bits per pixel (1 per RGB channel), 8 bits per byte
        long totalBits = (long) width * height * 3;
        this.capacityBytes = totalBits / 8;
    }
    
    /**
     * Creates a carrier from an existing BufferedImage.
     *
     * @param image the buffered image
     * @param format the image format (PNG or BMP)
     */
    public ImageCarrier(BufferedImage image, String format) {
        if (image == null) {
            throw new IllegalArgumentException("Image cannot be null");
        }
        
        this.image = image;
        this.width = image.getWidth();
        this.height = image.getHeight();
        this.format = format;
        
        long totalBits = (long) width * height * 3;
        this.capacityBytes = totalBits / 8;
    }
    
    /**
     * Returns the embedding capacity in bytes.
     *
     * @return maximum bytes that can be embedded
     */
    public long getCapacityBytes() {
        return capacityBytes;
    }
    
    /**
     * Returns the image width in pixels.
     */
    public int getWidth() {
        return width;
    }
    
    /**
     * Returns the image height in pixels.
     */
    public int getHeight() {
        return height;
    }
    
    /**
     * Returns the image format (PNG or BMP).
     */
    public String getFormat() {
        return format;
    }
    
    /**
     * Returns the underlying BufferedImage.
     *
     * @return the image data
     */
    public BufferedImage getImage() {
        return image;
    }
    
    /**
     * Gets the RGB value of a pixel.
     *
     * @param x the x coordinate
     * @param y the y coordinate
     * @return RGB value as packed integer
     */
    public int getRGB(int x, int y) {
        return image.getRGB(x, y);
    }
    
    /**
     * Sets the RGB value of a pixel.
     *
     * @param x the x coordinate
     * @param y the y coordinate
     * @param rgb the RGB value as packed integer
     */
    public void setRGB(int x, int y, int rgb) {
        image.setRGB(x, y, rgb);
    }
    
    /**
     * Saves the carrier image to file.
     *
     * @param outputFile the destination file
     * @throws IOException if writing fails
     */
    public void save(File outputFile) throws IOException {
        if (outputFile == null) {
            throw new IllegalArgumentException("Output file cannot be null");
        }
        
        boolean success = ImageIO.write(image, format, outputFile);
        if (!success) {
            throw new IOException("Failed to write image in format: " + format);
        }
    }
    
    /**
     * Validates that a payload can fit in this carrier.
     *
     * @param payloadSize the payload size in bytes
     * @throws IllegalArgumentException if payload is too large
     */
    public void validateCapacity(int payloadSize) {
        if (payloadSize < 0) {
            throw new IllegalArgumentException("Payload size cannot be negative");
        }
        
        if (payloadSize > capacityBytes) {
            throw new IllegalArgumentException(
                String.format(
                    "Payload too large: %d bytes required, but carrier capacity is %d bytes. " +
                    "Use a larger image (current: %dx%d pixels).",
                    payloadSize,
                    capacityBytes,
                    width,
                    height
                )
            );
        }
    }
    
    /**
     * Returns a human-readable capacity description.
     *
     * @return capacity description
     */
    public String getCapacityDescription() {
        return String.format(
            "%dx%d pixels, capacity: %s (%d bytes)",
            width,
            height,
            formatBytes(capacityBytes),
            capacityBytes
        );
    }
    
    /**
     * Formats bytes in human-readable form.
     */
    private static String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        } else if (bytes < 1024 * 1024) {
            return String.format("%.2f KB", bytes / 1024.0);
        } else {
            return String.format("%.2f MB", bytes / (1024.0 * 1024));
        }
    }
    
    @Override
    public String toString() {
        return String.format(
            "ImageCarrier[%s, %dx%d, capacity=%s]",
            format,
            width,
            height,
            formatBytes(capacityBytes)
        );
    }
}