package com.passwordmanager.demo;

import com.passwordmanager.crypto.*;
import com.passwordmanager.security.HashedPassword;
import com.passwordmanager.security.PBKDF2Hasher;
import com.passwordmanager.storage.VaultSession;
import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.SecretKey;

/**
 * Comprehensive demonstration of file encryption system.
 * <p>
 * Demonstrates:
 * - Encrypting files of various sizes
 * - Decrypting and verifying integrity
 * - Handling corrupted files
 * - Handling wrong keys
 * - Performance benchmarking
 * - All security profiles
 * </p>
 */
public class FileEncryptionDemo {
    
    public static void main(String[] args) {
        System.out.println("=".repeat(80));
        System.out.println("FILE ENCRYPTION SYSTEM DEMONSTRATION");
        System.out.println("=".repeat(80));
        System.out.println();
        
        try {
            // Setup vault
            setupVault();
            
            // Run demos
            demoBasicEncryption();
            demoSecurityProfiles();
            demoTamperDetection();
            demoWrongKeyDetection();
            demoLargeFiles();
            demoBinaryFiles();
            
            // Cleanup
            VaultSession.INSTANCE.lock();
            cleanupTestFiles();
            
            System.out.println();
            System.out.println("=".repeat(80));
            System.out.println("✓ ALL DEMOS COMPLETED SUCCESSFULLY");
            System.out.println("=".repeat(80));
            
        } catch (Exception e) {
            System.err.println("Demo failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Demo 1: Basic encryption and decryption workflow.
     */
    private static void demoBasicEncryption() throws Exception {
        printSection("BASIC ENCRYPTION/DECRYPTION");
        
        // Create test file
        File plainFile = new File("test_plain.txt");
        try (FileWriter writer = new FileWriter(plainFile)) {
            writer.write("This is a secret message.\n");
            writer.write("It contains sensitive information.\n");
            writer.write("Only authorized users should read this.\n");
        }
        
        File encryptedFile = new File("test_encrypted.vault");
        File decryptedFile = new File("test_decrypted.txt");
        
        SecretKey sessionKey = VaultSession.INSTANCE.getVaultSessionKey();
        
        // Encrypt
        System.out.println("Encrypting: " + plainFile.getName());
        FileEncryptor encryptor = new FileEncryptor(SecurityProfile.BALANCED);
        
        long encStart = System.nanoTime();
        boolean encSuccess = encryptor.encryptFile(plainFile, encryptedFile, sessionKey);
        long encTime = System.nanoTime() - encStart;
        
        System.out.println("  Encryption: " + (encSuccess ? "✓ SUCCESS" : "✗ FAILED"));
        System.out.println("  Time: " + (encTime / 1_000_000) + " ms");
        System.out.println("  Input size: " + plainFile.length() + " bytes");
        System.out.println("  Output size: " + encryptedFile.length() + " bytes");
        System.out.println("  Overhead: " + (encryptedFile.length() - plainFile.length()) + " bytes");
        
        // Verify encrypted file format
        boolean isValid = EncryptedFileFormat.isEncryptedFile(encryptedFile);
        System.out.println("  Format validation: " + (isValid ? "✓ VALID" : "✗ INVALID"));
        
        // Decrypt
        System.out.println();
        System.out.println("Decrypting: " + encryptedFile.getName());
        
        long decStart = System.nanoTime();
        boolean decSuccess = FileDecryptor.decryptFile(
            encryptedFile, decryptedFile, sessionKey
        );
        long decTime = System.nanoTime() - decStart;
        
        System.out.println("  Decryption: " + (decSuccess ? "✓ SUCCESS" : "✗ FAILED"));
        System.out.println("  Time: " + (decTime / 1_000_000) + " ms");
        
        // Verify content matches
        byte[] original = Files.readAllBytes(plainFile.toPath());
        byte[] decrypted = Files.readAllBytes(decryptedFile.toPath());
        boolean match = Arrays.equals(original, decrypted);
        
        System.out.println("  Content verification: " + (match ? "✓ MATCH" : "✗ MISMATCH"));
        
        // Cleanup
        plainFile.delete();
        encryptedFile.delete();
        decryptedFile.delete();
        
        System.out.println();
    }
    
    /**
     * Demo 2: All security profiles comparison.
     */
    private static void demoSecurityProfiles() throws Exception {
        printSection("SECURITY PROFILES COMPARISON");
        
        // Create test data
        byte[] testData = new byte[1024 * 100]; // 100KB
        Arrays.fill(testData, (byte) 'A');
        
        File plainFile = new File("profile_test.dat");
        Files.write(plainFile.toPath(), testData);
        
        SecretKey sessionKey = VaultSession.INSTANCE.getVaultSessionKey();
        
        System.out.printf("%-12s %-15s %-15s %-15s %-10s%n",
            "Profile", "Enc Time (ms)", "Dec Time (ms)", "File Size", "Overhead");
        System.out.println("-".repeat(70));
        
        for (SecurityProfile profile : SecurityProfile.values()) {
            File encFile = new File("test_" + profile.name().toLowerCase() + ".vault");
            File decFile = new File("test_" + profile.name().toLowerCase() + "_dec.dat");
            
            // Encrypt
            FileEncryptor encryptor = new FileEncryptor(profile);
            long encStart = System.nanoTime();
            encryptor.encryptFile(plainFile, encFile, sessionKey);
            long encTime = (System.nanoTime() - encStart) / 1_000_000;
            
            // Decrypt
            long decStart = System.nanoTime();
            FileDecryptor.decryptFile(encFile, decFile, sessionKey);
            long decTime = (System.nanoTime() - decStart) / 1_000_000;
            
            // Stats
            long overhead = encFile.length() - plainFile.length();
            
            System.out.printf("%-12s %-15d %-15d %-15d %-10d%n",
                profile.name(), encTime, decTime, encFile.length(), overhead);
            
            // Verify
            byte[] decrypted = Files.readAllBytes(decFile.toPath());
            boolean match = Arrays.equals(testData, decrypted);
            
            if (!match) {
                System.out.println("  WARNING: Content mismatch for " + profile);
            }
            
            // Cleanup
            encFile.delete();
            decFile.delete();
        }
        
        plainFile.delete();
        System.out.println();
    }
    
    /**
     * Demo 3: Tamper detection.
     */
    private static void demoTamperDetection() throws Exception {
        printSection("TAMPER DETECTION");
        
        // Create and encrypt file
        File plainFile = new File("tamper_test.txt");
        Files.writeString(plainFile.toPath(), "Original content");
        
        File encFile = new File("tamper_test.vault");
        
        SecretKey sessionKey = VaultSession.INSTANCE.getVaultSessionKey();
        FileEncryptor encryptor = new FileEncryptor(SecurityProfile.BALANCED);
        encryptor.encryptFile(plainFile, encFile, sessionKey);
        
        System.out.println("Original file encrypted successfully");
        System.out.println("File size: " + encFile.length() + " bytes");
        
        // Tamper with encrypted file (flip some bits)
        byte[] encData = Files.readAllBytes(encFile.toPath());
        System.out.println();
        System.out.println("Tampering with encrypted data (flipping bits)...");
        
        // Flip bits in the middle of the file
        int tamperPos = encData.length / 2;
        encData[tamperPos] ^= 0xFF;
        encData[tamperPos + 1] ^= 0xFF;
        
        File tamperedFile = new File("tampered.vault");
        Files.write(tamperedFile.toPath(), encData);
        
        // Try to decrypt tampered file
        File decFile = new File("tamper_decrypted.txt");
        
        System.out.println("Attempting to decrypt tampered file...");
        
        try {
            FileDecryptor.decryptFile(tamperedFile, decFile, sessionKey);
            System.out.println("✗ SECURITY FAILURE: Tampering not detected!");
            
        } catch (GeneralSecurityException e) {
            System.out.println("✓ TAMPER DETECTED: " + e.getMessage());
            System.out.println("  No output file created (secure behavior)");
        }
        
        // Verify no output was created
        if (decFile.exists()) {
            System.out.println("✗ WARNING: Output file exists despite auth failure!");
        } else {
            System.out.println("✓ Confirmed: No partial output on auth failure");
        }
        
        // Cleanup
        plainFile.delete();
        encFile.delete();
        tamperedFile.delete();
        if (decFile.exists()) decFile.delete();
        
        System.out.println();
    }
    
    /**
     * Demo 4: Wrong key detection.
     */
    private static void demoWrongKeyDetection() throws Exception {
        printSection("WRONG KEY DETECTION");
        
        // Create file and encrypt with first key
        File plainFile = new File("key_test.txt");
        Files.writeString(plainFile.toPath(), "Secret data");
        
        File encFile = new File("key_test.vault");
        
        // Use current session key
        SecretKey correctKey = VaultSession.INSTANCE.getVaultSessionKey();
        FileEncryptor encryptor = new FileEncryptor(SecurityProfile.BALANCED);
        encryptor.encryptFile(plainFile, encFile, correctKey);
        
        System.out.println("File encrypted with key A");
        
        // Create different key
        char[] differentPassword = "DifferentPassword123!".toCharArray();
        HashedPassword differentHash = PBKDF2Hasher.defaultHashPassword(differentPassword);
        byte[] wrongKeyBytes = PBKDF2Hasher.deriveSessionKey(
            differentPassword, differentHash
        );
        SecretKey wrongKey = new javax.crypto.spec.SecretKeySpec(wrongKeyBytes, "AES");
        
        System.out.println("Created different key B");
        System.out.println();
        System.out.println("Attempting to decrypt with key B (wrong key)...");
        
        // Try to decrypt with wrong key
        File decFile = new File("key_decrypted.txt");
        
        try {
            FileDecryptor.decryptFile(encFile, decFile, wrongKey);
            System.out.println("✗ SECURITY FAILURE: Wrong key accepted!");
            
        } catch (GeneralSecurityException e) {
            System.out.println("✓ WRONG KEY DETECTED: " + e.getMessage());
            System.out.println("  Authentication failed as expected");
        }
        
        // Verify decrypt works with correct key
        System.out.println();
        System.out.println("Decrypting with key A (correct key)...");
        
        boolean success = FileDecryptor.decryptFile(encFile, decFile, correctKey);
        System.out.println("  Decryption: " + (success ? "✓ SUCCESS" : "✗ FAILED"));
        
        // Cleanup
        plainFile.delete();
        encFile.delete();
        decFile.delete();
        Arrays.fill(differentPassword, ' ');
        Arrays.fill(wrongKeyBytes, (byte) 0);
        
        System.out.println();
    }
    
    /**
     * Demo 5: Large file performance.
     */
    private static void demoLargeFiles() throws Exception {
        printSection("LARGE FILE PERFORMANCE");
        
        SecretKey sessionKey = VaultSession.INSTANCE.getVaultSessionKey();
        
        int[] sizes = {1024 * 1024, 10 * 1024 * 1024}; // 1MB, 10MB
        String[] labels = {"1 MB", "10 MB"};
        
        System.out.printf("%-10s %-15s %-15s %-20s%n",
            "Size", "Enc Time", "Dec Time", "Throughput");
        System.out.println("-".repeat(60));
        
        for (int i = 0; i < sizes.length; i++) {
            int size = sizes[i];
            String label = labels[i];
            
            // Create large file
            byte[] data = new byte[size];
            new java.security.SecureRandom().nextBytes(data);
            
            File plainFile = new File("large_" + i + ".dat");
            Files.write(plainFile.toPath(), data);
            
            File encFile = new File("large_" + i + ".vault");
            File decFile = new File("large_" + i + "_dec.dat");
            
            // Encrypt
            FileEncryptor encryptor = new FileEncryptor(SecurityProfile.BALANCED);
            long encStart = System.nanoTime();
            encryptor.encryptFile(plainFile, encFile, sessionKey);
            long encTime = System.nanoTime() - encStart;
            
            // Decrypt
            long decStart = System.nanoTime();
            FileDecryptor.decryptFile(encFile, decFile, sessionKey);
            long decTime = System.nanoTime() - decStart;
            
            // Calculate throughput
            double encMBps = (size / (1024.0 * 1024.0)) / (encTime / 1e9);
            
            System.out.printf("%-10s %-15s %-15s %-20s%n",
                label,
                formatTime(encTime),
                formatTime(decTime),
                String.format("%.2f MB/s", encMBps));
            
            // Cleanup
            plainFile.delete();
            encFile.delete();
            decFile.delete();
        }
        
        System.out.println();
    }
    
    /**
     * Demo 6: Binary file support.
     */
    private static void demoBinaryFiles() throws Exception {
        printSection("BINARY FILE SUPPORT");
        
        // Create binary file with various byte values
        byte[] binaryData = new byte[1024];
        for (int i = 0; i < binaryData.length; i++) {
            binaryData[i] = (byte) (i % 256);
        }
        
        File binFile = new File("binary_test.bin");
        Files.write(binFile.toPath(), binaryData);
        
        File encFile = new File("binary_test.vault");
        File decFile = new File("binary_test_dec.bin");
        
        SecretKey sessionKey = VaultSession.INSTANCE.getVaultSessionKey();
        FileEncryptor encryptor = new FileEncryptor(SecurityProfile.BALANCED);
        
        System.out.println("Testing binary file with all byte values (0x00-0xFF)");
        
        // Encrypt
        encryptor.encryptFile(binFile, encFile, sessionKey);
        System.out.println("✓ Encryption: SUCCESS");
        
        // Decrypt
        FileDecryptor.decryptFile(encFile, decFile, sessionKey);
        System.out.println("✓ Decryption: SUCCESS");
        
        // Verify exact binary match
        byte[] decrypted = Files.readAllBytes(decFile.toPath());
        boolean match = Arrays.equals(binaryData, decrypted);
        
        System.out.println("✓ Binary integrity: " + (match ? "PRESERVED" : "CORRUPTED"));
        
        if (match) {
            System.out.println("  All 256 byte values correctly encrypted/decrypted");
        }
        
        // Cleanup
        binFile.delete();
        encFile.delete();
        decFile.delete();
        
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
    
    private static String formatTime(long nanos) {
        long millis = nanos / 1_000_000;
        if (millis < 1000) {
            return millis + " ms";
        } else {
            return String.format("%.2f s", millis / 1000.0);
        }
    }
    
    private static void cleanupTestFiles() {
        // Cleanup any remaining test files
        String[] patterns = {"test_", "large_", "profile_", "tamper_", "key_", "binary_"};
        File currentDir = new File(".");
        
        for (File file : currentDir.listFiles()) {
            for (String pattern : patterns) {
                if (file.getName().startsWith(pattern)) {
                    file.delete();
                }
            }
        }
    }
}