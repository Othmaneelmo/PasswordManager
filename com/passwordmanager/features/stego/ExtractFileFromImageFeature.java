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
 * Feature for extracting hidden files from steganographic images.
 * <p>
 * This feature:
 * - Loads a steganographic image
 * - Extracts embedded encrypted data
 * - Decrypts using the vault session key
 * - Verifies authentication tag
 * - Saves the recovered file
 * </p>
 * 
 * <p><b>Security Properties:</b></p>
 * <ul>
 *   <li>Authentication verified before extraction</li>
 *   <li>Tampered images rejected</li>
 *   <li>Wrong key causes authentication failure</li>
 *   <li>No partial extraction on failure</li>
 * </ul>
 */
public final class ExtractFileFromImageFeature extends AbstractFeature {
    private final VaultSession vaultSession;

    public ExtractFileFromImageFeature(VaultSession vaultSession) {
        super(
            "extract-file-image",
            "Extract File from Image",
            "Extracts a hidden file from a steganographic image"
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
        return 51;
    }

    @Override
    protected void executeInternal(Console console) {
        console.printf("%n");
        console.printf("=".repeat(60));
        console.printf("%n");
        console.printf("  EXTRACT FILE FROM IMAGE");
        console.printf("%n");
        console.printf("=".repeat(60));
        console.printf("%n%n");

        try {
            // Get steganographic image
            String imagePath = console.readLine("Enter path to steganographic image: ");
            if (imagePath == null || imagePath.trim().isEmpty()) {
                console.printf("ERROR: No image path provided.%n");
                return;
            }

            File imageFile = new File(imagePath.trim());
            if (!imageFile.exists()) {
                console.printf("ERROR: Image not found: %s%n", imagePath);
                return;
            }

            // Display image info
            ImageCarrier carrier = new ImageCarrier(imageFile);
            console.printf("%nSteganographic image: %s%n", imageFile.getName());
            console.printf("Dimensions: %dx%d pixels%n", carrier.getWidth(), carrier.getHeight());
            console.printf("Format: %s%n", carrier.getFormat());

            // Select security profile (must match embedding profile)
            SecurityProfile profile = selectSecurityProfile(console);
            if (profile == null) {
                console.printf("Operation cancelled.%n");
                return;
            }

            // Get output path
            console.printf("%n");
            String outputPath = console.readLine("Enter output file path: ");
            if (outputPath == null || outputPath.trim().isEmpty()) {
                console.printf("ERROR: No output path provided.%n");
                return;
            }

            File outputFile = new File(outputPath.trim());
            if (outputFile.exists()) {
                console.printf("ERROR: Output file already exists: %s%n", outputPath);
                return;
            }

            // Confirm extraction
            console.printf("%n");
            String confirm = console.readLine("Proceed with extraction? (yes/no): ");
            if (confirm == null || !confirm.trim().equalsIgnoreCase("yes")) {
                console.printf("Operation cancelled.%n");
                return;
            }

            // Perform extraction
            console.printf("%nExtracting and decrypting...%n");

            SecretKey sessionKey = vaultSession.getVaultSessionKey();
            StegoEngine engine = new StegoEngine(profile);

            long startTime = System.currentTimeMillis();
            String originalFilename = engine.extractFile(imageFile, outputFile, sessionKey);
            long duration = System.currentTimeMillis() - startTime;

            // Success
            console.printf("%n✓ File successfully extracted!%n");
            console.printf("✓ Authentication verified - file integrity confirmed%n");
            console.printf("  Original filename: %s%n", originalFilename);
            console.printf("  Saved to: %s%n", outputFile.getAbsolutePath());
            console.printf("  Size: %s%n", formatFileSize(outputFile.length()));
            console.printf("  Time: %s%n", formatDuration(duration));

        } catch (javax.crypto.AEADBadTagException e) {
            console.printf("%n✗ AUTHENTICATION FAILED%n");
            console.printf("  This means one of the following:%n");
            console.printf("  - Wrong vault master key%n");
            console.printf("  - Image has been tampered with or corrupted%n");
            console.printf("  - Image was created with a different vault%n");
            console.printf("  - Wrong security profile selected%n");
            console.printf("%n  No output file was created (security measure).%n");

        } catch (java.security.GeneralSecurityException e) {
            console.printf("%n✗ EXTRACTION FAILED%n");
            console.printf("  %s%n", e.getMessage());

            if (e.getMessage().contains("Authentication failed")) {
                console.printf("%n  Possible causes:%n");
                console.printf("  - Incorrect master key%n");
                console.printf("  - Image corruption or tampering%n");
                console.printf("  - Wrong security profile%n");
            }

        } catch (java.io.IOException e) {
            console.printf("%n✗ EXTRACTION FAILED%n");
            console.printf("  %s%n", e.getMessage());

            if (e.getMessage().contains("Invalid magic bytes")) {
                console.printf("%n  This image does not contain hidden data,%n");
                console.printf("  or the data is not in the expected format.%n");
            }

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
        console.printf("%nSelect security profile (must match hiding profile):%n");
        console.printf("  1. FAST     - AES-128-GCM%n");
        console.printf("  2. BALANCED - AES-256-GCM (most common)%n");
        console.printf("  3. PARANOID - AES-256-GCM with extended IV%n");
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