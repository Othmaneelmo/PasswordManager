package com.passwordmanager.features;

import com.passwordmanager.crypto.EncryptedFileFormat;
import com.passwordmanager.crypto.FileDecryptor;
import com.passwordmanager.storage.VaultSession;
import java.io.Console;
import java.io.File;
import javax.crypto.SecretKey;

/**
 * Feature module for decrypting files via console interface.
 * <p>
 * Provides user-friendly file decryption with:
 * - Format validation
 * - Progress reporting
 * - Authentication verification
 * - Error handling and user feedback
 * </p>
 */
public class DecryptFileFeature implements Feature {

    @Override
    public String getId() {
        return "decrypt-file";
    }

    @Override
    public String getDisplayName() {
        return "Decrypt File";
    }

    @Override
    public String getDescription() {
        return "Decrypt a file with authentication verification to ensure data integrity.";
    }

    @Override
    public boolean requiresUnlockedVault() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public FeatureCategory getCategory() {
        return FeatureCategory.FILE_MANAGEMENT;
    }

    @Override
    public int getSortOrder() {
        return 20;
    }

    /**
     * Executes the decrypt file feature.
     * <p>
     * Interactive flow:
     * 1. Check vault is unlocked
     * 2. Prompt for encrypted file path
     * 3. Validate file format
     * 4. Prompt for output file path
     * 5. Decrypt with progress display
     * 6. Report success or error
     * </p>
     *
     * @param console console for user interaction
     */
    @Override
    public void execute(Console console) {
        if (console == null) {
            System.out.println("ERROR: Console not available");
            return;
        }
        
        System.out.println();
        System.out.println("=".repeat(60));
        System.out.println("  FILE DECRYPTION");
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
            
            // Get encrypted file
            String inputPath = console.readLine("Enter path to encrypted file: ");
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
            
            // Validate file format
            if (!EncryptedFileFormat.isEncryptedFile(inputFile)) {
                System.out.println("ERROR: File is not a valid encrypted vault file.");
                System.out.println("The file does not have the correct format signature.");
                return;
            }
            
            // Display file info
            System.out.println();
            System.out.println("Encrypted file: " + inputFile.getName());
            System.out.println("Size: " + formatFileSize(inputFile.length()));
            System.out.println("Path: " + inputFile.getAbsolutePath());
            
            // Read header to show encryption info
            try {
                EncryptedFileFormat.FileMetadata metadata = 
                    readMetadataSafely(inputFile);
                
                if (metadata != null) {
                    System.out.println("Profile: " + metadata.getProfile().name());
                    System.out.println("Algorithm: " + 
                        metadata.getProfile().getTransformation());
                    metadata.zeroize();
                }
            } catch (Exception e) {
                System.out.println("Warning: Could not read file metadata");
            }
            
            System.out.println();
            
            // Get output file
            String outputPath = console.readLine("Enter output file path (decrypted): ");
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
            
            // Confirm decryption
            System.out.println();
            String confirm = console.readLine(
                "Decrypt '" + inputFile.getName() + "' to '" + 
                outputFile.getName() + "'? (yes/no): "
            );
            
            if (confirm == null || !confirm.trim().equalsIgnoreCase("yes")) {
                System.out.println("Operation cancelled.");
                return;
            }
            
            // Decrypt with progress
            System.out.println();
            System.out.println("Decrypting and verifying authenticity...");
            
            long startTime = System.currentTimeMillis();
            
            boolean success = FileDecryptor.decryptFileWithProgress(
                inputFile,
                outputFile,
                sessionKey,
                new ProgressReporter(inputFile.length())
            );
            
            long duration = System.currentTimeMillis() - startTime;
            
            System.out.println(); // New line after progress
            
            if (success) {
                System.out.println("✓ Decryption successful!");
                System.out.println("✓ Authentication verified - file integrity confirmed");
                System.out.println("  Output: " + outputFile.getAbsolutePath());
                System.out.println("  Size: " + formatFileSize(outputFile.length()));
                System.out.println("  Time: " + formatDuration(duration));
                System.out.println("  Throughput: " + 
                    formatThroughput(inputFile.length(), duration));
            } else {
                System.out.println("✗ Decryption failed");
            }
            
        } catch (javax.crypto.AEADBadTagException e) {
            System.out.println();
            System.out.println("✗ AUTHENTICATION FAILED");
            System.out.println("  This means one of the following:");
            System.out.println("  - Wrong vault master key");
            System.out.println("  - File has been tampered with or corrupted");
            System.out.println("  - File was encrypted with a different vault");
            System.out.println();
            System.out.println("  No output file was created (security measure).");
            
        } catch (java.security.GeneralSecurityException e) {
            System.out.println();
            System.out.println("✗ DECRYPTION FAILED");
            System.out.println("  " + e.getMessage());
            
            if (e.getMessage().contains("Authentication failed")) {
                System.out.println();
                System.out.println("  Possible causes:");
                System.out.println("  - Incorrect master key");
                System.out.println("  - File corruption or tampering");
            }
            
        } catch (Exception e) {
            System.out.println();
            System.out.println("✗ Decryption failed: " + e.getMessage());
            
            if (e.getCause() != null) {
                System.out.println("  Cause: " + e.getCause().getMessage());
            }
        }
        
        System.out.println();
    }
    
    /**
     * Safely reads file metadata without throwing exceptions.
     */
    private static EncryptedFileFormat.FileMetadata readMetadataSafely(File file) {
        try (java.io.InputStream in = new java.io.BufferedInputStream(
                new java.io.FileInputStream(file))) {
            return EncryptedFileFormat.readHeader(in);
        } catch (Exception e) {
            return null;
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
    private static class ProgressReporter implements FileDecryptor.ProgressCallback {
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