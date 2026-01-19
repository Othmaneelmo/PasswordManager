package com.passwordmanager.features.stego;

import com.passwordmanager.crypto.SecurityProfile;
import com.passwordmanager.features.AbstractFeature;
import com.passwordmanager.features.FeatureCategory;
import com.passwordmanager.stego.ImageCarrier;
import com.passwordmanager.stego.StegoEngine;
import com.passwordmanager.storage.VaultSession;

import javax.crypto.SecretKey;
import java.io.Console;
import java.io.File;

/**
 * Feature for hiding files inside images using steganography.
 * <p>
 * This feature:
 * - Encrypts a secret file using the vault session key
 * - Embeds the encrypted data into a carrier image
 * - Preserves visual appearance of the carrier
 * - Creates a steganographic image indistinguishable from the original
 * </p>
 * 
 * <p><b>Security Properties:</b></p>
 * <ul>
 *   <li>Secret file is encrypted before embedding</li>
 *   <li>Authentication tag prevents tampering</li>
 *   <li>No plaintext data touches disk</li>
 *   <li>Visual analysis cannot reveal payload</li>
 * </ul>
 */
public final class HideFileInImageFeature extends AbstractFeature {
    private final VaultSession vaultSession;

    public HideFileInImageFeature(VaultSession vaultSession) {
        super(
            "hide-file-image",
            "Hide File in Image",
            "Hides a file inside an image using LSB steganography with encryption"
        );

        if (vaultSession == null) {
            throw new IllegalArgumentException("VaultSession cannot be null");
        }

        this.vaultSession = vaultSession;
    }

    @Override
    public boolean requiresUnlockedVault() {
        return true;
    }

    @Override
    public FeatureCategory getCategory() {
        return FeatureCategory.FILE_MANAGEMENT;
    }

    @Override
    public int getSortOrder() {
        return 50;
    }

    @Override
    protected void executeInternal(Console console) {
        console.printf("%n");
        console.printf("=".repeat(60));
        console.printf("%n");
        console.printf("  HIDE FILE IN IMAGE");
        console.printf("%n");
        console.printf("=".repeat(60));
        console.printf("%n%n");

        try {
            // Get secret file
            String secretPath = console.readLine("Enter path to file to hide: ");
            if (secretPath == null || secretPath.trim().isEmpty()) {
                console.printf("ERROR: No file path provided.%n");
                return;
            }

            File secretFile = new File(secretPath.trim());
            if (!secretFile.exists()) {
                console.printf("ERROR: File not found: %s%n", secretPath);
                return;
            }

            // Display secret file info
            console.printf("%nSecret file: %s%n", secretFile.getName());
            console.printf("Size: %s%n", formatFileSize(secretFile.length()));

            // Get carrier image
            console.printf("%n");
            String carrierPath = console.readLine("Enter path to carrier image (PNG/BMP): ");
            if (carrierPath == null || carrierPath.trim().isEmpty()) {
                console.printf("ERROR: No image path provided.%n");
                return;
            }

            File carrierFile = new File(carrierPath.trim());
            if (!carrierFile.exists()) {
                console.printf("ERROR: Image not found: %s%n", carrierPath);
                return;
            }

            // Load and display carrier info
            ImageCarrier carrier = new ImageCarrier(carrierFile);
            console.printf("%nCarrier image: %s%n", carrierFile.getName());
            console.printf("Dimensions: %dx%d pixels%n", carrier.getWidth(), carrier.getHeight());
            console.printf("Capacity: %s%n", formatFileSize(carrier.getCapacityBytes()));

            // Select security profile
            SecurityProfile profile = selectSecurityProfile(console);
            if (profile == null) {
                console.printf("Operation cancelled.%n");
                return;
            }

            // Calculate requirements
            int ivSize = profile.getIvBytes();
            int tagSize = profile.getTagBits() / 8;
            int headerSize = 14 + secretFile.getName().getBytes().length;
            long totalNeeded = secretFile.length() + ivSize + tagSize + headerSize;

            console.printf("%nSpace required: %s%n", formatFileSize(totalNeeded));
            console.printf("Carrier capacity: %s%n", formatFileSize(carrier.getCapacityBytes()));

            if (totalNeeded > carrier.getCapacityBytes()) {
                console.printf("%nERROR: File too large for carrier image.%n");
                console.printf("Required: %s, Available: %s%n",
                    formatFileSize(totalNeeded),
                    formatFileSize(carrier.getCapacityBytes()));
                console.printf("%nSuggestion: Use a larger image or compress the file.%n");
                return;
            }

            double usagePercent = (totalNeeded * 100.0) / carrier.getCapacityBytes();
            console.printf("Capacity usage: %.1f%%%n", usagePercent);

            // Get output path
            console.printf("%n");
            String outputPath = console.readLine("Enter output image path: ");
            if (outputPath == null || outputPath.trim().isEmpty()) {
                console.printf("ERROR: No output path provided.%n");
                return;
            }

            File outputFile = new File(outputPath.trim());
            if (outputFile.exists()) {
                console.printf("ERROR: Output file already exists: %s%n", outputPath);
                return;
            }

            // Confirm operation
            console.printf("%n");
            console.printf("Summary:%n");
            console.printf("  Secret file: %s (%s)%n", 
                secretFile.getName(), formatFileSize(secretFile.length()));
            console.printf("  Carrier: %s (%dx%d)%n", 
                carrierFile.getName(), carrier.getWidth(), carrier.getHeight());
            console.printf("  Profile: %s%n", profile.name());
            console.printf("  Output: %s%n", outputFile.getName());
            console.printf("%n");

            String confirm = console.readLine("Proceed with hiding? (yes/no): ");
            if (confirm == null || !confirm.trim().equalsIgnoreCase("yes")) {
                console.printf("Operation cancelled.%n");
                return;
            }

            // Perform steganography
            console.printf("%nProcessing...%n");

            SecretKey sessionKey = vaultSession.getVaultSessionKey();
            StegoEngine engine = new StegoEngine(profile);

            long startTime = System.currentTimeMillis();
            engine.hideFile(secretFile, carrierFile, outputFile, sessionKey);
            long duration = System.currentTimeMillis() - startTime;

            // Success
            console.printf("%n✓ File successfully hidden!%n");
            console.printf("  Output: %s%n", outputFile.getAbsolutePath());
            console.printf("  Size: %s%n", formatFileSize(outputFile.length()));
            console.printf("  Time: %s%n", formatDuration(duration));
            console.printf("%n");
            console.printf("NOTE: The output image looks identical to the carrier.%n");
            console.printf("      The hidden file is encrypted and authenticated.%n");
            console.printf("      You need the vault key to extract it.%n");

        } catch (Exception e) {
            console.printf("%n✗ Error: %s%n", e.getMessage());
            if (Boolean.getBoolean("vault.debug")) {
                e.printStackTrace();
            }
        }

        console.printf("%nPress ENTER to continue...");
        console.readLine();
    }

    private SecurityProfile selectSecurityProfile(Console console) {
        console.printf("%nSelect security profile:%n");
        console.printf("  1. FAST     - AES-128-GCM (smaller overhead)%n");
        console.printf("  2. BALANCED - AES-256-GCM (recommended)%n");
        console.printf("  3. PARANOID - AES-256-GCM with extended IV (maximum security)%n");
        console.printf("  0. Cancel%n");

        String choice = console.readLine("%nChoice: ");

        switch (choice) {
            case "1": return SecurityProfile.FAST;
            case "2": return SecurityProfile.BALANCED;
            case "3": return SecurityProfile.PARANOID;
            case "0": return null;
            default:
                console.printf("Invalid choice. Using BALANCED.%n");
                return SecurityProfile.BALANCED;
        }
    }

    private static String formatFileSize(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        } else if (bytes < 1024 * 1024) {
            return String.format("%.2f KB", bytes / 1024.0);
        } else if (bytes < 1024 * 1024 * 1024) {
            return String.format("%.2f MB", bytes / (1024.0 * 1024));
        } else {
            return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
        }
    }

    private static String formatDuration(long millis) {
        if (millis < 1000) {
            return millis + " ms";
        } else {
            return String.format("%.2f s", millis / 1000.0);
        }
    }
}