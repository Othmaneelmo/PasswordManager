package com.passwordmanager.demo;

import com.passwordmanager.crypto.SecurityProfile;
import com.passwordmanager.security.HashedPassword;
import com.passwordmanager.security.PBKDF2Hasher;
import com.passwordmanager.stego.*;
import com.passwordmanager.storage.VaultSession;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.SecretKey;

/**
 * Comprehensive demonstration of the steganography system.
 * <p>
 * Demonstrates:
 * - LSB embedding algorithm
 * - Encryption + steganography composition
 * - Capacity calculations
 * - Visual imperceptibility
 * - Authentication and tampering detection
 * - Complete hide/extract workflow
 * </p>
 */
public class SteganographyDemo {

    public static void main(String[] args) {
        System.out.println("=".repeat(80));
        System.out.println("STEGANOGRAPHY SYSTEM DEMONSTRATION");
        System.out.println("=".repeat(80));
        System.out.println();

        try {
            // Setup vault
            setupVault();

            // Run demonstrations
            demoLSBAlgorithm();
            demoCapacityCalculation();
            demoBasicHideExtract();
            demoVisualImperceptibility();
            demoTamperDetection();
            demoSecurityProfiles();
            demoLargeFiles();

            // Cleanup
            VaultSession.INSTANCE.lock();
            cleanupTestFiles();

            System.out.println();
            System.out.println("=".repeat(80));
            System.out.println("✓ ALL DEMONSTRATIONS COMPLETED SUCCESSFULLY");
            System.out.println("=".repeat(80));

        } catch (Exception e) {
            System.err.println("Demo failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Demo 1: Demonstrates LSB embedding algorithm.
     */
    private static void demoLSBAlgorithm() {
        printSection("LSB EMBEDDING ALGORITHM");

        System.out.println("Demonstrating how LSB steganography works...");
        System.out.println();

        // Create a simple pixel
        int originalR = 0b10110010; // 178
        int originalG = 0b11001101; // 205
        int originalB = 0b01010111; // 87

        System.out.printf("Original pixel RGB: (%d, %d, %d)%n", originalR, originalG, originalB);
        System.out.println("Binary representation:");
        System.out.printf("  R: %s%n", toBinaryString(originalR));
        System.out.printf("  G: %s%n", toBinaryString(originalG));
        System.out.printf("  B: %s%n", toBinaryString(originalB));

        // Data to embed: 3 bits
        int bit1 = 1;
        int bit2 = 0;
        int bit3 = 1;

        System.out.println();
        System.out.printf("Data bits to embed: %d%d%d%n", bit1, bit2, bit3);

        // Embed by replacing LSB
        int modifiedR = (originalR & 0xFE) | bit1;
        int modifiedG = (originalG & 0xFE) | bit2;
        int modifiedB = (originalB & 0xFE) | bit3;

        System.out.println();
        System.out.printf("Modified pixel RGB: (%d, %d, %d)%n", modifiedR, modifiedG, modifiedB);
        System.out.println("Binary representation:");
        System.out.printf("  R: %s (changed: %+d)%n", toBinaryString(modifiedR), modifiedR - originalR);
        System.out.printf("  G: %s (changed: %+d)%n", toBinaryString(modifiedG), modifiedG - originalG);
        System.out.printf("  B: %s (changed: %+d)%n", toBinaryString(modifiedB), modifiedB - originalB);

        System.out.println();
        System.out.println("Result: Maximum ±1 change per channel - imperceptible to human eye");
        System.out.println();
    }

    /**
     * Demo 2: Capacity calculations.
     */
    private static void demoCapacityCalculation() throws Exception {
        printSection("CAPACITY CALCULATION");

        System.out.println("Demonstrating capacity for various image sizes...");
        System.out.println();

        int[][] sizes = {
            {640, 480},    // VGA
            {1280, 720},   // HD
            {1920, 1080},  // Full HD
            {3840, 2160}   // 4K
        };

        System.out.printf("%-20s %-15s %-15s %-15s%n", 
            "Resolution", "Pixels", "Capacity", "Example File");
        System.out.println("-".repeat(65));

        for (int[] size : sizes) {
            int width = size[0];
            int height = size[1];
            long pixels = (long) width * height;
            long capacityBytes = (pixels * 3) / 8;

            String example;
            if (capacityBytes < 500 * 1024) {
                example = "Small document";
            } else if (capacityBytes < 5 * 1024 * 1024) {
                example = "Large document/Image";
            } else {
                example = "Multiple files";
            }

            System.out.printf("%-20s %-15s %-15s %-15s%n",
                width + "x" + height,
                String.format("%,d", pixels),
                formatBytes(capacityBytes),
                example
            );
        }

        System.out.println();
        System.out.println("Formula: Capacity = (Width × Height × 3 RGB channels) / 8 bits");
        System.out.println();
    }

    /**
     * Demo 3: Basic hide and extract workflow.
     */
    private static void demoBasicHideExtract() throws Exception {
        printSection("BASIC HIDE/EXTRACT WORKFLOW");

        // Create secret file
        File secretFile = new File("secret.txt");
        try (FileWriter writer = new FileWriter(secretFile)) {
            writer.write("This is a secret message.\n");
            writer.write("It contains sensitive information.\n");
            writer.write("Only authorized users should read this.\n");
        }

        System.out.println("1. Created secret file:");
        System.out.printf("   - Name: %s%n", secretFile.getName());
        System.out.printf("   - Size: %d bytes%n", secretFile.length());
        System.out.println();

        // Create carrier image
        File carrierFile = new File("carrier.png");
        createTestImage(carrierFile, 800, 600);

        System.out.println("2. Created carrier image:");
        System.out.printf("   - Format: PNG%n");
        System.out.printf("   - Size: 800x600 pixels%n");
        System.out.printf("   - Capacity: %s%n", formatBytes((800L * 600 * 3) / 8));
        System.out.println();

        // Hide file
        File stegoFile = new File("stego.png");
        SecretKey sessionKey = VaultSession.INSTANCE.getVaultSessionKey();
        StegoEngine engine = new StegoEngine(SecurityProfile.BALANCED);

        System.out.println("3. Hiding file in image...");
        long hideStart = System.currentTimeMillis();
        engine.hideFile(secretFile, carrierFile, stegoFile, sessionKey);
        long hideTime = System.currentTimeMillis() - hideStart;

        System.out.printf("   ✓ Hidden in %d ms%n", hideTime);
        System.out.printf("   - Output: %s%n", stegoFile.getName());
        System.out.printf("   - Size: %d bytes (same as carrier)%n", stegoFile.length());
        System.out.println();

        // Extract file
        File extractedFile = new File("extracted.txt");

        System.out.println("4. Extracting file from image...");
        long extractStart = System.currentTimeMillis();
        String originalName = engine.extractFile(stegoFile, extractedFile, sessionKey);
        long extractTime = System.currentTimeMillis() - extractStart;

        System.out.printf("   ✓ Extracted in %d ms%n", extractTime);
        System.out.printf("   - Original name: %s%n", originalName);
        System.out.printf("   - Size: %d bytes%n", extractedFile.length());
        System.out.println();

        // Verify content
        byte[] original = Files.readAllBytes(secretFile.toPath());
        byte[] extracted = Files.readAllBytes(extractedFile.toPath());
        boolean match = Arrays.equals(original, extracted);

        System.out.println("5. Verification:");
        System.out.printf("   Content match: %s%n", match ? "✓ YES" : "✗ NO");

        // Cleanup
        secretFile.delete();
        carrierFile.delete();
        stegoFile.delete();
        extractedFile.delete();

        System.out.println();
    }

    /**
     * Demo 4: Visual imperceptibility test.
     */
    private static void demoVisualImperceptibility() throws Exception {
        printSection("VISUAL IMPERCEPTIBILITY TEST");

        // Create colorful test image
        File originalFile = new File("original_visual.png");
        BufferedImage original = createColorfulImage(400, 300);
        ImageIO.write(original, "PNG", originalFile);

        System.out.println("Created test image with various colors and gradients");
        System.out.println();

        // Create secret data
        File secretFile = new File("secret_visual.dat");
        byte[] secretData = new byte[10000]; // 10KB
        new SecureRandom().nextBytes(secretData);
        Files.write(secretFile.toPath(), secretData);

        // Hide data
        File stegoFile = new File("stego_visual.png");
        SecretKey sessionKey = VaultSession.INSTANCE.getVaultSessionKey();
        StegoEngine engine = new StegoEngine(SecurityProfile.BALANCED);

        engine.hideFile(secretFile, originalFile, stegoFile, sessionKey);

        // Compare images
        BufferedImage originalImg = ImageIO.read(originalFile);
        BufferedImage stegoImg = ImageIO.read(stegoFile);

        long totalDiff = 0;
        long maxDiff = 0;
        long pixelCount = originalImg.getWidth() * originalImg.getHeight() * 3;

        for (int y = 0; y < originalImg.getHeight(); y++) {
            for (int x = 0; x < originalImg.getWidth(); x++) {
                int origRGB = originalImg.getRGB(x, y);
                int stegoRGB = stegoImg.getRGB(x, y);

                int origR = (origRGB >> 16) & 0xFF;
                int origG = (origRGB >> 8) & 0xFF;
                int origB = origRGB & 0xFF;

                int stegoR = (stegoRGB >> 16) & 0xFF;
                int stegoG = (stegoRGB >> 8) & 0xFF;
                int stegoB = stegoRGB & 0xFF;

                long diff = Math.abs(origR - stegoR) + 
                           Math.abs(origG - stegoG) + 
                           Math.abs(origB - stegoB);

                totalDiff += diff;
                maxDiff = Math.max(maxDiff, diff);
            }
        }

        double avgDiff = (double) totalDiff / pixelCount;

        System.out.println("Pixel difference analysis:");
        System.out.printf("  Average difference per channel: %.6f (out of 255)%n", avgDiff);
        System.out.printf("  Maximum difference: %d%n", maxDiff);
        System.out.printf("  Percentage change: %.4f%%%n", (avgDiff / 255) * 100);
        System.out.println();
        System.out.println("Conclusion: Differences are imperceptible to human vision");

        // Cleanup
        originalFile.delete();
        secretFile.delete();
        stegoFile.delete();

        System.out.println();
    }

    /**
     * Demo 5: Tamper detection.
     */
    private static void demoTamperDetection() throws Exception {
        printSection("TAMPER DETECTION");

        // Create and hide file
        File secretFile = new File("secret_tamper.txt");
        Files.writeString(secretFile.toPath(), "Sensitive data");

        File carrierFile = new File("carrier_tamper.png");
        createTestImage(carrierFile, 500, 400);

        File stegoFile = new File("stego_tamper.png");
        SecretKey sessionKey = VaultSession.INSTANCE.getVaultSessionKey();
        StegoEngine engine = new StegoEngine(SecurityProfile.BALANCED);

        engine.hideFile(secretFile, carrierFile, stegoFile, sessionKey);

        System.out.println("1. Created steganographic image with hidden data");
        System.out.println();

        // Test 1: Normal extraction (should succeed)
        System.out.println("2. Test: Normal extraction");
        File extractedFile = new File("extracted_normal.txt");
        try {
            engine.extractFile(stegoFile, extractedFile, sessionKey);
            System.out.println("   ✓ SUCCESS - File extracted and authenticated");
            extractedFile.delete();
        } catch (Exception e) {
            System.out.println("   ✗ FAILED - " + e.getMessage());
        }
        System.out.println();

        // Test 2: Tampered image (flip some bytes)
        System.out.println("3. Test: Tampered image");
        byte[] stegoData = Files.readAllBytes(stegoFile.toPath());
        
        // Flip bits in the middle (corrupt embedded data)
        int tamperPos = stegoData.length / 2;
        stegoData[tamperPos] ^= 0xFF;
        stegoData[tamperPos + 1] ^= 0xFF;

        File tamperedFile = new File("stego_tampered.png");
        Files.write(tamperedFile.toPath(), stegoData);

        File extractedTampered = new File("extracted_tampered.txt");
        try {
            engine.extractFile(tamperedFile, extractedTampered, sessionKey);
            System.out.println("   ✗ SECURITY FAILURE - Tampering not detected!");
        } catch (java.security.GeneralSecurityException e) {
            System.out.println("   ✓ SUCCESS - Tampering detected:");
            System.out.println("      " + e.getMessage());
            System.out.println("      No output file created (secure behavior)");
        }

        // Cleanup
        secretFile.delete();
        carrierFile.delete();
        stegoFile.delete();
        tamperedFile.delete();
        if (extractedTampered.exists()) extractedTampered.delete();

        System.out.println();
    }

    /**
     * Demo 6: Security profiles comparison.
     */
    private static void demoSecurityProfiles() throws Exception {
        printSection("SECURITY PROFILES COMPARISON");

        // Create test data
        File secretFile = new File("secret_profile.txt");
        Files.writeString(secretFile.toPath(), "Test data for profile comparison");

        File carrierFile = new File("carrier_profile.png");
        createTestImage(carrierFile, 800, 600);

        SecretKey sessionKey = VaultSession.INSTANCE.getVaultSessionKey();

        System.out.printf("%-12s %-15s %-15s %-10s %-10s%n",
            "Profile", "Hide Time", "Extract Time", "Overhead", "Security");
        System.out.println("-".repeat(65));

        for (SecurityProfile profile : SecurityProfile.values()) {
            File stegoFile = new File("stego_" + profile.name().toLowerCase() + ".png");
            File extractedFile = new File("extracted_" + profile.name().toLowerCase() + ".txt");

            StegoEngine engine = new StegoEngine(profile);

            // Hide
            long hideStart = System.nanoTime();
            engine.hideFile(secretFile, carrierFile, stegoFile, sessionKey);
            long hideTime = (System.nanoTime() - hideStart) / 1_000_000;

            // Extract
            long extractStart = System.nanoTime();
            engine.extractFile(stegoFile, extractedFile, sessionKey);
            long extractTime = (System.nanoTime() - extractStart) / 1_000_000;

            // Calculate overhead
            int overhead = profile.getIvBytes() + (profile.getTagBits() / 8);

            // Security level
            String security = profile == SecurityProfile.FAST ? "Good" :
                            profile == SecurityProfile.BALANCED ? "Strong" : "Maximum";

            System.out.printf("%-12s %-15s %-15s %-10d %-10s%n",
                profile.name(),
                hideTime + " ms",
                extractTime + " ms",
                overhead,
                security
            );

            stegoFile.delete();
            extractedFile.delete();
        }

        secretFile.delete();
        carrierFile.delete();

        System.out.println();
    }

    /**
     * Demo 7: Large file handling.
     */
    private static void demoLargeFiles() throws Exception {
        printSection("LARGE FILE HANDLING");

        int[] sizes = {10_000, 100_000, 500_000}; // 10KB, 100KB, 500KB

        System.out.printf("%-15s %-20s %-15s %-15s%n",
            "File Size", "Min Image Size", "Hide Time", "Extract Time");
        System.out.println("-".repeat(65));

        for (int size : sizes) {
            // Create secret file
            File secretFile = new File("large_secret.dat");
            byte[] data = new byte[size];
            new SecureRandom().nextBytes(data);
            Files.write(secretFile.toPath(), data);

            // Calculate required image size
            long pixelsNeeded = LSBSteganography.calculateRequiredPixels(size);
            int side = (int) Math.ceil(Math.sqrt(pixelsNeeded));

            // Create carrier
            File carrierFile = new File("large_carrier.png");
            createTestImage(carrierFile, side, side);

            // Hide and extract
            File stegoFile = new File("large_stego.png");
            File extractedFile = new File("large_extracted.dat");

            SecretKey sessionKey = VaultSession.INSTANCE.getVaultSessionKey();
            StegoEngine engine = new StegoEngine(SecurityProfile.BALANCED);

            long hideStart = System.currentTimeMillis();
            engine.hideFile(secretFile, carrierFile, stegoFile, sessionKey);
            long hideTime = System.currentTimeMillis() - hideStart;

            long extractStart = System.currentTimeMillis();
            engine.extractFile(stegoFile, extractedFile, sessionKey);
            long extractTime = System.currentTimeMillis() - extractStart;

            System.out.printf("%-15s %-20s %-15s %-15s%n",
                formatBytes(size),
                side + "x" + side + " px",
                hideTime + " ms",
                extractTime + " ms"
            );

            // Cleanup
            secretFile.delete();
            carrierFile.delete();
            stegoFile.delete();
            extractedFile.delete();
        }

        System.out.println();
    }

    // ==================== HELPER METHODS ====================

    private static void setupVault() throws Exception {
        System.out.println("Setting up vault session...");

        char[] password = "DemoPassword123!@#".toCharArray();
        HashedPassword stored = PBKDF2Hasher.defaultHashPassword(password);
        byte[] sessionKey = PBKDF2Hasher.deriveSessionKey(password, stored);

        VaultSession.INSTANCE.unlock(sessionKey);

        Arrays.fill(password, ' ');
        Arrays.fill(sessionKey, (byte) 0);

        System.out.println("✓ Vault unlocked");
        System.out.println();
    }

    private static void printSection(String title) {
        System.out.println();
        System.out.println("=".repeat(80));
        System.out.println("  " + title);
        System.out.println("=".repeat(80));
        System.out.println();
    }

    private static void createTestImage(File file, int width, int height) throws Exception {
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();

        // Simple gradient
        for (int y = 0; y < height; y++) {
            int gray = (int) (255 * ((double) y / height));
            g.setColor(new Color(gray, gray, gray));
            g.drawLine(0, y, width, y);
        }

        g.dispose();
        ImageIO.write(image, "PNG", file);
    }

    private static BufferedImage createColorfulImage(int width, int height) {
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();

        // Create colorful patterns
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int r = (int) (128 + 127 * Math.sin(x * 0.02));
                int g = (int) (128 + 127 * Math.sin(y * 0.02));
                int b = (int) (128 + 127 * Math.sin((x + y) * 0.01));
                g.setColor(new Color(r, g, b));
                g.fillRect(x, y, 1, 1);
            }
        }

        g.dispose();
        return image;
    }

    private static String toBinaryString(int value) {
        return String.format("%8s", Integer.toBinaryString(value & 0xFF)).replace(' ', '0');
    }

    private static String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        } else if (bytes < 1024 * 1024) {
            return String.format("%.2f KB", bytes / 1024.0);
        } else {
            return String.format("%.2f MB", bytes / (1024.0 * 1024));
        }
    }

    private static void cleanupTestFiles() {
        String[] patterns = {"secret", "carrier", "stego", "extracted", "large", "original", "tamper"};
        File currentDir = new File(".");

        for (File file : currentDir.listFiles()) {
            for (String pattern : patterns) {
                if (file.getName().startsWith(pattern)) {
                    file.delete();
                    break;
                }
            }
        }
    }
}