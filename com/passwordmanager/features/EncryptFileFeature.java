package com.passwordmanager.features;

import com.passwordmanager.crypto.FileEncryptor;
import com.passwordmanager.crypto.SecurityProfile;
import com.passwordmanager.storage.VaultSession;

import javax.crypto.SecretKey;
import java.io.Console;
import java.io.File;

/**
 * Feature module for encrypting files via console interface.
 * <p>
 * Provides user-friendly file encryption with:
 * - Security profile selection
 * - Progress reporting
 * - Error handling and user feedback
 * - File validation
 * </p>
 */
public class EncryptFileFeature {
    
    /**
     * Executes the encrypt file feature.
     * <p>
     * Interactive flow:
     * 1. Check vault is unlocked
     * 2. Prompt for input file path
     * 3. Prompt for output file path
     * 4. Select security profile
     * 5. Encrypt with progress display
     * 6. Report success or error
     * </p>
     *
     * @param console console for user interaction
     */
    public static void execute(Console console) {
        if (console == null) {
            System.out.println("ERROR: Console not available");
            return;
        }
        
        System.out.println();
        System.out.println("=".repeat(60));
        System.out.println("  FILE ENCRYPTION");
        System.out.println("=".repeat(60));
        System.out.println();
        
        // Check vault is unlocked
        if (!VaultSession.INSTANCE.isUnlocked()) {
            System.out.println("ERROR: Vault is locked. Unlock the vault first.");
            return;
        }
        
        try {
            // Get session key
            SecretKey sessionKey = VaultSession.INSTANCE.getVaultSessionKey();
            
            // Get input file
            String inputPath = console.readLine("Enter path to file to encrypt: ");
            if (inputPath == null || inputPath.trim().isEmpty()) {
                System.out.println("ERROR: No file path provided.");
                return;
            }
            
            File inputFile = new File(inputPath.trim());
            if (!inputFile.exists()) {
                System.out.println("ERROR: File not found: " + inputPath);
                return;
            }
            if (!inputFile.canRead()) {
                System.out.println("ERROR: Cannot read file: " + inputPath);
                return;
            }
            if (inputFile.length() == 0) {
                System.out.println("ERROR: File is empty.");
                return;
            }
            
            // Display file info
            System.out.println();
            System.out.println("File: " + inputFile.getName());
            System.out.println("Size: " + formatFileSize(inputFile.length()));
            System.out.println("Path: " + inputFile.getAbsolutePath());
            System.out.println();
            
            // Get output file
            String outputPath = console.readLine("Enter output file path (encrypted): ");
            if (outputPath == null || outputPath.trim().isEmpty()) {
                System.out.println("ERROR: No output path provided.");
                return;
            }
            
            File outputFile = new File(outputPath.trim());
            if (outputFile.exists()) {
                System.out.println("ERROR: Output file already exists: " + outputPath);
                System.out.println("Choose a different path or delete the existing file.");
                return;
            }
            
            // Select security profile
            SecurityProfile profile = selectSecurityProfile(console);
            if (profile == null) {
                System.out.println("Operation cancelled.");
                return;
            }
            
            System.out.println();
            System.out.println("Encrypting with profile: " + profile.name());
            System.out.println(profile.getDescription());
            System.out.println();
            
            // Create encryptor
            FileEncryptor encryptor = new FileEncryptor(profile);
            
            // Encrypt with progress
            System.out.println("Encrypting... ");
            
            long startTime = System.currentTimeMillis();
            
            boolean success = encryptor.encryptFileWithProgress(
                inputFile, 
                outputFile, 
                sessionKey,
                new ProgressReporter(inputFile.length())
            );
            
            long duration = System.currentTimeMillis() - startTime;
            
            System.out.println(); // New line after progress
            
            if (success) {
                System.out.println("✓ Encryption successful!");
                System.out.println("  Output: " + outputFile.getAbsolutePath());
                System.out.println("  Size: " + formatFileSize(outputFile.length()));
                System.out.println("  Time: " + formatDuration(duration));
                System.out.println("  Throughput: " + 
                    formatThroughput(inputFile.length(), duration));
            } else {
                System.out.println("✗ Encryption failed");
            }
            
        } catch (Exception e) {
            System.out.println();
            System.out.println("✗ Encryption failed: " + e.getMessage());
            
            if (e.getCause() != null) {
                System.out.println("  Cause: " + e.getCause().getMessage());
            }
        }
        
        System.out.println();
    }
    
    /**
     * Prompts user to select security profile.
     */
    private static SecurityProfile selectSecurityProfile(Console console) {
        System.out.println("Select security profile:");
        System.out.println("  1. FAST     - AES-128-GCM (fastest, good for non-critical files)");
        System.out.println("  2. BALANCED - AES-256-GCM (recommended default)");
        System.out.println("  3. PARANOID - AES-256-GCM with extended IV (maximum security)");
        System.out.println();
        
        String choice = console.readLine("Enter choice [1-3] (default: 2): ");
        if (choice == null || choice.trim().isEmpty()) {
            return SecurityProfile.BALANCED;
        }
        
        switch (choice.trim()) {
            case "1": return SecurityProfile.FAST;
            case "2": return SecurityProfile.BALANCED;
            case "3": return SecurityProfile.PARANOID;
            default:
                System.out.println("Invalid choice. Using BALANCED.");
                return SecurityProfile.BALANCED;
        }
    }
    
    /**
     * Formats file size in human-readable format.
     */
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
    
    /**
     * Formats duration in human-readable format.
     */
    private static String formatDuration(long millis) {
        if (millis < 1000) {
            return millis + " ms";
        } else if (millis < 60000) {
            return String.format("%.2f s", millis / 1000.0);
        } else {
            long seconds = millis / 1000;
            long minutes = seconds / 60;
            seconds = seconds % 60;
            return String.format("%d min %d sec", minutes, seconds);
        }
    }
    
    /**
     * Formats throughput in human-readable format.
     */
    private static String formatThroughput(long bytes, long millis) {
        if (millis == 0) return "N/A";
        
        double bytesPerSec = (bytes * 1000.0) / millis;
        
        if (bytesPerSec < 1024 * 1024) {
            return String.format("%.2f KB/s", bytesPerSec / 1024);
        } else {
            return String.format("%.2f MB/s", bytesPerSec / (1024 * 1024));
        }
    }
    
    /**
     * Progress reporter with console output.
     */
    private static class ProgressReporter implements FileEncryptor.ProgressCallback {
        private final long totalBytes;
        private long lastReportedPercent = -1;
        
        ProgressReporter(long totalBytes) {
            this.totalBytes = totalBytes;
        }
        
        @Override
        public void onProgress(long bytesProcessed, long totalBytes) {
            long percent = (bytesProcessed * 100) / this.totalBytes;
            
            // Report every 5%
            if (percent != lastReportedPercent && percent % 5 == 0) {
                System.out.print("\r  Progress: " + percent + "% (" + 
                    formatFileSize(bytesProcessed) + " / " + 
                    formatFileSize(this.totalBytes) + ")");
                lastReportedPercent = percent;
            }
        }
    }
}