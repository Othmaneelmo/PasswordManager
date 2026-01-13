package com.passwordmanager.features.encryption;

import com.passwordmanager.crypto.AesGcmProvider;
import com.passwordmanager.crypto.EncryptionProvider;
import com.passwordmanager.crypto.EncryptionResult;
import com.passwordmanager.crypto.SecurityProfile;
import com.passwordmanager.features.AbstractFeature;
import com.passwordmanager.features.FeatureCategory;
import com.passwordmanager.storage.VaultSession;

import javax.crypto.SecretKey;
import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Feature for encrypting text data using the vault session key.
 * <p>
 * This feature:
 * - Prompts the user for plaintext input
 * - Allows selection of security profile
 * - Encrypts the data using AES-GCM
 * - Displays the encrypted result as Base64
 * </p>
 * 
 * <p><b>Security Notes:</b></p>
 * <ul>
 *   <li>Plaintext is read as a password (hidden input)</li>
 *   <li>Plaintext is zeroized after encryption</li>
 *   <li>Ciphertext is safe to display (it's encrypted)</li>
 * </ul>
 */
public final class EncryptDataFeature extends AbstractFeature {
    private final VaultSession vaultSession;

    /**
     * Constructs the encrypt data feature.
     *
     * @param vaultSession the vault session (dependency injected)
     * @throws IllegalArgumentException if vaultSession is null
     */
    public EncryptDataFeature(VaultSession vaultSession) {
        super(
            "encrypt-data",
            "Encrypt Data",
            "Encrypts text using the vault session key with AES-GCM encryption"
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
        return FeatureCategory.ENCRYPTION;
    }

    @Override
    public int getSortOrder() {
        return 10; // First in encryption category
    }

    @Override
    protected void executeInternal(Console console) {
        console.printf("%n=== Encrypt Data ===%n");
        console.printf("This feature encrypts text data using AES-GCM.%n%n");

        // Select security profile
        SecurityProfile profile = selectSecurityProfile(console);
        if (profile == null) {
            return; // User cancelled
        }

        // Get plaintext from user
        console.printf("%nEnter the text to encrypt (input hidden):%n");
        char[] plaintextChars = console.readPassword("> ");

        if (plaintextChars == null || plaintextChars.length == 0) {
            console.printf("Error: No input provided.%n");
            return;
        }

        byte[] plaintext = null;
        EncryptionResult encrypted = null;

        try {
            // Convert to bytes
            plaintext = new String(plaintextChars).getBytes(StandardCharsets.UTF_8);

            // Get session key
            SecretKey sessionKey = vaultSession.getVaultSessionKey();

            // Create provider and encrypt
            EncryptionProvider provider = new AesGcmProvider(profile);
            encrypted = provider.encrypt(plaintext, sessionKey);

            // Display result
            displayEncryptionResult(console, encrypted, profile);

        } catch (IllegalStateException e) {
            console.printf("Error: %s%n", e.getMessage());
        } catch (GeneralSecurityException e) {
            console.printf("Encryption failed: %s%n", e.getMessage());
        } finally {
            // Clean up sensitive data
            if (plaintextChars != null) {
                Arrays.fill(plaintextChars, ' ');
            }
            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
        }

        console.printf("%nPress ENTER to continue...");
        console.readLine();
    }

    /**
     * Prompts the user to select a security profile.
     */
    private SecurityProfile selectSecurityProfile(Console console) {
        console.printf("Select security profile:%n");
        console.printf("  1. FAST     - AES-128-GCM (fastest)%n");
        console.printf("  2. BALANCED - AES-256-GCM (recommended)%n");
        console.printf("  3. PARANOID - AES-256-GCM with extended IV (maximum security)%n");
        console.printf("  0. Cancel%n");
        console.printf("%nChoice: ");

        String choice = console.readLine();

        switch (choice) {
            case "1":
                return SecurityProfile.FAST;
            case "2":
                return SecurityProfile.BALANCED;
            case "3":
                return SecurityProfile.PARANOID;
            case "0":
                console.printf("Cancelled.%n");
                return null;
            default:
                console.printf("Invalid choice. Using BALANCED profile.%n");
                return SecurityProfile.BALANCED;
        }
    }

    /**
     * Displays the encryption result in a user-friendly format.
     */
    private void displayEncryptionResult(Console console, EncryptionResult encrypted, 
                                        SecurityProfile profile) {
        console.printf("%n=== Encryption Successful ===%n");
        console.printf("Profile: %s%n", profile.name());
        console.printf("IV size: %d bytes%n", encrypted.getIv().length);
        console.printf("Ciphertext size: %d bytes%n", encrypted.getCiphertextSize());
        console.printf("Overhead: %d bytes%n", encrypted.getOverheadBytes());
        console.printf("%n--- Encrypted Data (Base64) ---%n");

        // Encode IV and ciphertext as Base64 for transport/storage
        String ivBase64 = Base64.getEncoder().encodeToString(encrypted.getIv());
        String ciphertextBase64 = Base64.getEncoder().encodeToString(encrypted.getCiphertext());

        console.printf("IV: %s%n", ivBase64);
        console.printf("Ciphertext: %s%n", ciphertextBase64);

        console.printf("%n--- Combined Format (for decryption) ---%n");
        // Format: <profile>:<iv>:<ciphertext>
        String combined = String.format("%s:%s:%s", 
            profile.name(), ivBase64, ciphertextBase64);
        console.printf("%s%n", combined);

        console.printf("%nCopy the combined format above to decrypt later.%n");
    }
}