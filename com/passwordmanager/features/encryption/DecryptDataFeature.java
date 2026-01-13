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
 * Feature for decrypting data that was encrypted with {@link EncryptDataFeature}.
 * <p>
 * This feature:
 * - Accepts the combined format: {@code <profile>:<iv>:<ciphertext>}
 * - Validates and parses the input
 * - Decrypts using the vault session key
 * - Displays the plaintext result
 * </p>
 * 
 * <p><b>Security Notes:</b></p>
 * <ul>
 *   <li>Authentication tag is verified before displaying plaintext</li>
 *   <li>Plaintext is zeroized after display</li>
 *   <li>Tampering with ciphertext is detected and rejected</li>
 * </ul>
 */
public final class DecryptDataFeature extends AbstractFeature {
    private final VaultSession vaultSession;

    /**
     * Constructs the decrypt data feature.
     *
     * @param vaultSession the vault session (dependency injected)
     * @throws IllegalArgumentException if vaultSession is null
     */
    public DecryptDataFeature(VaultSession vaultSession) {
        super(
            "decrypt-data",
            "Decrypt Data",
            "Decrypts data that was encrypted using the Encrypt Data feature"
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
        return 20; // Second in encryption category
    }

    @Override
    protected void executeInternal(Console console) {
        console.printf("%n=== Decrypt Data ===%n");
        console.printf("This feature decrypts data encrypted with the Encrypt Data feature.%n");
        console.printf("Expected format: <profile>:<iv>:<ciphertext>%n%n");

        // Get encrypted data from user
        console.printf("Paste the encrypted data (combined format):%n");
        String encryptedData = console.readLine("> ");

        if (encryptedData == null || encryptedData.trim().isEmpty()) {
            console.printf("Error: No input provided.%n");
            return;
        }

        byte[] decrypted = null;

        try {
            // Parse the combined format
            ParsedEncryptedData parsed = parseEncryptedData(encryptedData);

            // Get session key
            SecretKey sessionKey = vaultSession.getVaultSessionKey();

            // Create provider and decrypt
            EncryptionProvider provider = new AesGcmProvider(parsed.profile);
            decrypted = provider.decrypt(parsed.encryptionResult, sessionKey);

            // Display result
            displayDecryptionResult(console, decrypted);

        } catch (IllegalArgumentException e) {
            console.printf("Parsing error: %s%n", e.getMessage());
        } catch (IllegalStateException e) {
            console.printf("Error: %s%n", e.getMessage());
        } catch (GeneralSecurityException e) {
            console.printf("Decryption failed: %s%n", e.getMessage());
            console.printf("Possible causes:%n");
            console.printf("  - Data was tampered with%n");
            console.printf("  - Wrong encryption key used%n");
            console.printf("  - Corrupted ciphertext%n");
        } finally {
            // Clean up sensitive data
            if (decrypted != null) {
                Arrays.fill(decrypted, (byte) 0);
            }
        }

        console.printf("%nPress ENTER to continue...");
        console.readLine();
    }

    /**
     * Parses the combined encrypted data format.
     * <p>
     * Expected format: {@code <profile>:<iv>:<ciphertext>}
     * </p>
     *
     * @param data the combined format string
     * @return parsed components
     * @throws IllegalArgumentException if format is invalid
     */
    private ParsedEncryptedData parseEncryptedData(String data) {
        String[] parts = data.trim().split(":", 3);

        if (parts.length != 3) {
            throw new IllegalArgumentException(
                "Invalid format. Expected: <profile>:<iv>:<ciphertext>"
            );
        }

        // Parse profile
        SecurityProfile profile;
        try {
            profile = SecurityProfile.valueOf(parts[0].trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                "Invalid security profile: " + parts[0] + ". " +
                "Valid values: FAST, BALANCED, PARANOID"
            );
        }

        // Parse IV
        byte[] iv;
        try {
            iv = Base64.getDecoder().decode(parts[1].trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid IV: not valid Base64");
        }

        // Parse ciphertext
        byte[] ciphertext;
        try {
            ciphertext = Base64.getDecoder().decode(parts[2].trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid ciphertext: not valid Base64");
        }

        // Create EncryptionResult
        EncryptionResult encryptionResult = new EncryptionResult(iv, ciphertext, profile);

        return new ParsedEncryptedData(profile, encryptionResult);
    }

    /**
     * Displays the decrypted plaintext.
     */
    private void displayDecryptionResult(Console console, byte[] decrypted) {
        console.printf("%n=== Decryption Successful ===%n");

        // Try to decode as UTF-8 text
        try {
            String plaintext = new String(decrypted, StandardCharsets.UTF_8);
            console.printf("Decrypted text:%n%s%n", plaintext);
        } catch (Exception e) {
            // If not valid UTF-8, show as hex
            console.printf("Decrypted data (hex): ");
            for (byte b : decrypted) {
                console.printf("%02x", b);
            }
            console.printf("%n");
        }

        console.printf("%nDecrypted size: %d bytes%n", decrypted.length);
    }

    /**
     * Container for parsed encrypted data components.
     */
    private static class ParsedEncryptedData {
        final SecurityProfile profile;
        final EncryptionResult encryptionResult;

        ParsedEncryptedData(SecurityProfile profile, EncryptionResult encryptionResult) {
            this.profile = profile;
            this.encryptionResult = encryptionResult;
        }
    }
}