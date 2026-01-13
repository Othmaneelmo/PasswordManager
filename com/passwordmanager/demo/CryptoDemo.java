package com.passwordmanager.demo;

import com.passwordmanager.crypto.AesGcmProvider;
import com.passwordmanager.crypto.EncryptionProvider;
import com.passwordmanager.crypto.EncryptionResult;
import com.passwordmanager.crypto.SecurityProfile;
import com.passwordmanager.security.HashedPassword;
import com.passwordmanager.security.PBKDF2Hasher;
import com.passwordmanager.storage.VaultSession;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.SecretKey;

/**
 * Demonstration of the encryption abstraction layer.
 * <p>
 * Shows how to:
 * </p>
 * <ul>
 *   <li>Create encryption providers with different security profiles</li>
 *   <li>Encrypt and decrypt data using the vault session key</li>
 *   <li>Handle multiple security levels</li>
 *   <li>Properly clean up sensitive data</li>
 * </ul>
 * 
 * <p><b>Usage:</b></p>
 * <pre>
 * javac com/passwordmanager/demo/CryptoDemo.java
 * java com.passwordmanager.demo.CryptoDemo
 * </pre>
 */
public class CryptoDemo {

    public static void main(String[] args) {
        System.out.println("=".repeat(80));
        System.out.println("ENCRYPTION ABSTRACTION LAYER DEMO");
        System.out.println("=".repeat(80));
        System.out.println();

        try {
            // Setup: Create and unlock vault session
            System.out.println("--- Setup: Creating Vault Session ---");
            char[] masterPassword = "DemoPassword123!@#".toCharArray();
            HashedPassword stored = PBKDF2Hasher.defaultHashPassword(masterPassword);
            byte[] sessionKey = PBKDF2Hasher.deriveSessionKey(masterPassword, stored);
            VaultSession.INSTANCE.unlock(sessionKey);
            Arrays.fill(masterPassword, ' ');
            Arrays.fill(sessionKey, (byte) 0);
            System.out.println(" Vault unlocked");
            System.out.println();

            // Get the session key for encryption
            SecretKey vaultKey = VaultSession.INSTANCE.getVaultSessionKey();

            // Demo 1: Basic encryption/decryption with BALANCED profile
            demonstrateBasicEncryption(vaultKey);

            // Demo 2: Multiple security profiles
            demonstrateSecurityProfiles(vaultKey);

            // Demo 3: Error handling
            demonstrateErrorHandling(vaultKey);

            // Demo 4: Large data encryption
            demonstrateLargeData(vaultKey);

            // Cleanup
            VaultSession.INSTANCE.lock();
            System.out.println();
            System.out.println("=".repeat(80));
            System.out.println(" Demo completed successfully");
            System.out.println("=".repeat(80));

        } catch (Exception e) {
            System.err.println("Demo failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Demonstrates basic encryption and decryption with the BALANCED profile.
     */
    private static void demonstrateBasicEncryption(SecretKey vaultKey) 
            throws GeneralSecurityException {
        
        System.out.println("--- Demo 1: Basic Encryption/Decryption ---");
        
        // Create an encryption provider with BALANCED profile
        EncryptionProvider provider = new AesGcmProvider(SecurityProfile.BALANCED);
        System.out.println("Provider created: " + provider.getProfile().getDescription());

        // Prepare plaintext
        String secretMessage = "This is my secret password: MyP@ssw0rd!";
        byte[] plaintext = secretMessage.getBytes(StandardCharsets.UTF_8);
        System.out.println("Original plaintext: \"" + secretMessage + "\"");
        System.out.println("Plaintext size: " + plaintext.length + " bytes");

        // Encrypt
        EncryptionResult encrypted = provider.encrypt(plaintext, vaultKey);
        System.out.println(" Encrypted successfully");
        System.out.println("  IV size: " + encrypted.getIv().length + " bytes");
        System.out.println("  Ciphertext size: " + encrypted.getCiphertextSize() + " bytes");
        System.out.println("  Overhead: " + encrypted.getOverheadBytes() + " bytes");

        // Decrypt
        byte[] decrypted = provider.decrypt(encrypted, vaultKey);
        String decryptedMessage = new String(decrypted, StandardCharsets.UTF_8);
        System.out.println(" Decrypted successfully");
        System.out.println("Decrypted plaintext: \"" + decryptedMessage + "\"");

        // Verify
        boolean matches = Arrays.equals(plaintext, decrypted);
        System.out.println("Match: " + (matches ? " YES" : " NO"));

        // Cleanup
        Arrays.fill(plaintext, (byte) 0);
        Arrays.fill(decrypted, (byte) 0);
        encrypted.zeroize();

        System.out.println();
    }

    /**
     * Demonstrates encryption with different security profiles.
     */
    private static void demonstrateSecurityProfiles(SecretKey vaultKey) 
            throws GeneralSecurityException {
        
        System.out.println("--- Demo 2: Security Profiles Comparison ---");

        byte[] data = "Sensitive account data".getBytes(StandardCharsets.UTF_8);

        for (SecurityProfile profile : SecurityProfile.values()) {
            System.out.println("\nProfile: " + profile.name());
            System.out.println("  " + profile.getDescription());

            EncryptionProvider provider = new AesGcmProvider(profile);

            long startTime = System.nanoTime();
            EncryptionResult encrypted = provider.encrypt(data, vaultKey);
            long encryptTime = System.nanoTime() - startTime;

            startTime = System.nanoTime();
            byte[] decrypted = provider.decrypt(encrypted, vaultKey);
            long decryptTime = System.nanoTime() - startTime;

            System.out.println("  Encryption time: " + (encryptTime / 1000) + " μs");
            System.out.println("  Decryption time: " + (decryptTime / 1000) + " μs");
            System.out.println("  Ciphertext size: " + encrypted.getCiphertextSize() + " bytes");
            System.out.println("  Overhead: " + encrypted.getOverheadBytes() + " bytes");

            // Verify
            boolean matches = Arrays.equals(data, decrypted);
            System.out.println("  Verification: " + (matches ? " PASS" : " FAIL"));

            // Cleanup
            Arrays.fill(decrypted, (byte) 0);
            encrypted.zeroize();
        }

        Arrays.fill(data, (byte) 0);
        System.out.println();
    }

    /**
     * Demonstrates error handling and security properties.
     */
    private static void demonstrateErrorHandling(SecretKey vaultKey) 
            throws GeneralSecurityException {
        
        System.out.println("--- Demo 3: Error Handling & Security ---");

        EncryptionProvider provider = new AesGcmProvider(SecurityProfile.BALANCED);
        byte[] data = "Test data".getBytes(StandardCharsets.UTF_8);

        // Test 1: Tampering detection
        System.out.println("\nTest 1: Ciphertext tampering detection");
        EncryptionResult encrypted = provider.encrypt(data, vaultKey);
        
        // Tamper with ciphertext
        byte[] tamperedCiphertext = Arrays.copyOf(
            encrypted.getCiphertext(), 
            encrypted.getCiphertext().length
        );
        tamperedCiphertext[0] ^= 0xFF; // Flip bits
        
        EncryptionResult tampered = new EncryptionResult(
            encrypted.getIv(),
            tamperedCiphertext,
            encrypted.getProfile()
        );

        try {
            provider.decrypt(tampered, vaultKey);
            System.out.println("   FAIL: Should have detected tampering");
        } catch (GeneralSecurityException e) {
            System.out.println("   PASS: Tampering detected - " + e.getClass().getSimpleName());
        }

        // Test 2: IV uniqueness
        System.out.println("\nTest 2: IV uniqueness");
        EncryptionResult enc1 = provider.encrypt(data, vaultKey);
        EncryptionResult enc2 = provider.encrypt(data, vaultKey);
        boolean sameIv = Arrays.equals(enc1.getIv(), enc2.getIv());
        System.out.println("  Same IV: " + sameIv);
        System.out.println("  " + (sameIv ? " FAIL: IVs should be unique" : " PASS: IVs are unique"));

        // Test 3: Different ciphertexts for same plaintext
        boolean sameCiphertext = Arrays.equals(enc1.getCiphertext(), enc2.getCiphertext());
        System.out.println("  Same ciphertext: " + sameCiphertext);
        System.out.println("  " + (sameCiphertext ? " FAIL: Should produce different ciphertexts" : " PASS: Different ciphertexts"));

        // Cleanup
        Arrays.fill(data, (byte) 0);
        encrypted.zeroize();
        tampered.zeroize();
        enc1.zeroize();
        enc2.zeroize();

        System.out.println();
    }

    /**
     * Demonstrates encryption of larger data.
     */
    private static void demonstrateLargeData(SecretKey vaultKey) 
            throws GeneralSecurityException {
        
        System.out.println("--- Demo 4: Large Data Encryption ---");

        EncryptionProvider provider = new AesGcmProvider(SecurityProfile.BALANCED);

        // Test with increasing data sizes
        int[] sizes = {1024, 10240, 102400}; // 1KB, 10KB, 100KB

        for (int size : sizes) {
            byte[] data = new byte[size];
            Arrays.fill(data, (byte) 'A');

            long startTime = System.nanoTime();
            EncryptionResult encrypted = provider.encrypt(data, vaultKey);
            long encryptTime = System.nanoTime() - startTime;

            startTime = System.nanoTime();
            byte[] decrypted = provider.decrypt(encrypted, vaultKey);
            long decryptTime = System.nanoTime() - startTime;

            double encryptMBps = (size / 1024.0 / 1024.0) / (encryptTime / 1e9);
            double decryptMBps = (size / 1024.0 / 1024.0) / (decryptTime / 1e9);

            System.out.println("\nData size: " + (size / 1024) + " KB");
            System.out.println("  Encrypt time: " + (encryptTime / 1000000) + " ms (" + 
                              String.format("%.2f", encryptMBps) + " MB/s)");
            System.out.println("  Decrypt time: " + (decryptTime / 1000000) + " ms (" + 
                              String.format("%.2f", decryptMBps) + " MB/s)");
            System.out.println("  Overhead: " + encrypted.getOverheadBytes() + " bytes (" + 
                              String.format("%.2f", (encrypted.getOverheadBytes() * 100.0 / size)) + "%)");

            // Verify
            boolean matches = Arrays.equals(data, decrypted);
            System.out.println("  Verification: " + (matches ? " PASS" : " FAIL"));

            // Cleanup
            Arrays.fill(data, (byte) 0);
            Arrays.fill(decrypted, (byte) 0);
            encrypted.zeroize();
        }

        System.out.println();
    }
}