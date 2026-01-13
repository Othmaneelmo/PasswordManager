package com.passwordmanager.main;

import com.passwordmanager.features.*;
import com.passwordmanager.features.encryption.DecryptDataFeature;
import com.passwordmanager.features.encryption.EncryptDataFeature;
import com.passwordmanager.features.system.ExitFeature;
import com.passwordmanager.features.system.LockVaultFeature;
import com.passwordmanager.security.HashedPassword;
import com.passwordmanager.security.PBKDF2Hasher;
import com.passwordmanager.storage.VaultSession;
import com.passwordmanager.storage.VaultStorage;
import com.passwordmanager.validation.PasswordValidator;
import com.passwordmanager.validation.ValidationResult;
import java.io.Console;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Main entry point for the Password Manager application.
 * <p>
 * <b>Responsibilities:</b>
 * </p>
 * <ul>
 *   <li>Application startup and initialization</li>
 *   <li>Master key creation and verification</li>
 *   <li>Vault unlocking</li>
 *   <li>Feature registration</li>
 *   <li>Delegation to menu system</li>
 *   <li>Clean shutdown</li>
 * </ul>
 * 
 * <p><b>NOT Responsible For:</b></p>
 * <ul>
 *   <li>Feature-specific logic (delegated to Feature implementations)</li>
 *   <li>Menu display and navigation (delegated to FeatureMenu)</li>
 *   <li>Cryptographic operations (delegated to features and crypto layer)</li>
 * </ul>
 * 
 * <p><b>Design Principles:</b></p>
 * <ul>
 *   <li><b>Single Responsibility:</b> Main only handles bootstrap and teardown</li>
 *   <li><b>Dependency Injection:</b> Features receive dependencies explicitly</li>
 *   <li><b>Extensibility:</b> New features added by registration, not code changes</li>
 *   <li><b>Fail-Safe:</b> Errors during startup prevent vault access</li>
 * </ul>
 * 
 * <p><b>Application Flow:</b></p>
 * <pre>
 * 1. Check console availability
 * 2. Check if vault exists
 *    - If no: Create master key and save vault
 *    - If yes: Verify master key and unlock vault
 * 3. Register all features
 * 4. Start menu loop
 * 5. On exit: Lock vault and cleanup
 * </pre>
 */
public class Main {
    /**
     * Application entry point.
     *
     * @param args command-line arguments (ignored)
     */
    public static void main(String[] args) {
        Console console = System.console();
        if (console == null) {
            System.out.println("Console unavailable. Please run in a terminal environment.");
            return;
        }

        try {
            // Startup banner
            displayBanner(console);

            // Initialize vault (create or unlock)
            boolean vaultUnlocked = initializeVault(console);

            if (!vaultUnlocked) {
                console.printf("%nVault initialization failed. Exiting.%n");
                return;
            }

            // Create feature registry and register all features
            FeatureRegistry registry = new FeatureRegistry();
            registerFeatures(registry);

            // Create and run menu
            FeatureMenu menu = new FeatureMenu(registry, VaultSession.INSTANCE, console);
            menu.run();

        } catch (Exception e) {
            System.err.println("Fatal error: " + e.getMessage());
            if (Boolean.getBoolean("vault.debug")) {
                e.printStackTrace();
            }
        } finally {
            // Ensure vault is locked on exit
            VaultSession.INSTANCE.lock();
        }
    }

    /**
     * Displays the application startup banner.
     */
    private static void displayBanner(Console console) {
        console.printf("%n");
        console.printf("=".repeat(80));
        console.printf("%n");
        console.printf("                           PASSWORD MANAGER%n");
        console.printf("                         Secure Vault System%n");
        console.printf("=".repeat(80));
        console.printf("%n%n");
    }

    /**
     * Initializes the vault (creates or unlocks).
     *
     * @param console the console for user interaction
     * @return true if vault is unlocked, false otherwise
     */
    private static boolean initializeVault(Console console) throws IOException {
        if (!VaultStorage.exists()) {
            return createNewVault(console);
        } else {
            return unlockExistingVault(console);
        }
    }

    /**
     * Creates a new vault with a master key.
     */
    private static boolean createNewVault(Console console) throws IOException {
        console.printf("No vault found. Creating new vault...%n%n");

        char[] masterKeyChars = console.readPassword("Create a master key: ");

        if (masterKeyChars == null || masterKeyChars.length == 0) {
            console.printf("Error: Master key cannot be empty.%n");
            return false;
        }

        try {
            // Validate password strength
            ValidationResult vr = PasswordValidator.validate(masterKeyChars);
            if (!vr.ok()) {
                console.printf("Master key not strong enough:%n");
                for (String msg : vr.messages()) {
                    console.printf(" - %s%n", msg);
                }
                return false;
            }

            // Hash password
            HashedPassword encodedHash = PBKDF2Hasher.defaultHashPassword(masterKeyChars);
            console.printf("✓ Master key validated and hashed%n");

            // Save to vault
            VaultStorage.saveMasterKey(
                encodedHash.getAlgorithm(),
                encodedHash.getIterations(),
                encodedHash.getSalt(),
                encodedHash.getHash()
            );
            console.printf("✓ Vault created successfully%n%n");

            // Unlock vault with the same key
            byte[] sessionKey = PBKDF2Hasher.deriveSessionKey(masterKeyChars, encodedHash);
            VaultSession.INSTANCE.unlock(sessionKey);
            Arrays.fill(sessionKey, (byte) 0);

            console.printf("✓ Vault unlocked%n");

            return true;

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            console.printf("Cryptographic error: %s%n", e.getMessage());
            return false;
        } finally {
            Arrays.fill(masterKeyChars, ' ');
        }
    }

    /**
     * Unlocks an existing vault.
     */
    private static boolean unlockExistingVault(Console console) throws IOException {
        console.printf("Vault found. Please unlock...%n%n");

        // Allow up to 3 attempts
        for (int attempt = 1; attempt <= 3; attempt++) {
            char[] masterKeyChars = console.readPassword("Enter master key (attempt %d/3): ", attempt);

            if (masterKeyChars == null || masterKeyChars.length == 0) {
                console.printf("Error: Master key cannot be empty.%n");
                continue;
            }

            try {
                // Load stored hash
                HashedPassword stored = VaultStorage.loadHashedPassword();
                if (stored == null) {
                    console.printf("Error: Could not load master key from vault.%n");
                    return false;
                }

                // Verify password
                boolean verified = PBKDF2Hasher.verifyPassword(masterKeyChars, stored);

                if (verified) {
                    console.printf("✓ Master key verified%n");

                    // Derive session key and unlock vault
                    byte[] sessionKey = PBKDF2Hasher.deriveSessionKey(masterKeyChars, stored);

                    try {
                        VaultSession.INSTANCE.unlock(sessionKey);
                        console.printf("✓ Vault unlocked%n%n");
                        return true;
                    } finally {
                        Arrays.fill(sessionKey, (byte) 0);
                    }
                } else {
                    console.printf("✗ Incorrect master key%n%n");
                }

            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                console.printf("Cryptographic error: %s%n", e.getMessage());
                return false;
            } finally {
                Arrays.fill(masterKeyChars, ' ');
            }
        }

        console.printf("Maximum unlock attempts exceeded.%n");
        return false;
    }

    /**
     * Registers all available features with the registry.
     * <p>
     * <b>Adding New Features:</b>
     * </p>
     * <ol>
     *   <li>Implement the {@link Feature} interface (or extend {@link AbstractFeature})</li>
     *   <li>Add registration here: {@code registry.register(new YourFeature(...))}</li>
     *   <li>That's it! The feature automatically appears in the menu</li>
     * </ol>
     * <p>
     * Features are displayed in the menu based on:
     * - Category (ENCRYPTION, FILE_MANAGEMENT, etc.)
     * - Sort order within category
     * - Display name (alphabetically as tiebreaker)
     * </p>
     */
    private static void registerFeatures(FeatureRegistry registry) {
        // Encryption features
        registry.register(new EncryptDataFeature(VaultSession.INSTANCE));
        registry.register(new DecryptDataFeature(VaultSession.INSTANCE));

        // System features
        registry.register(new LockVaultFeature(VaultSession.INSTANCE));
        registry.register(new ExitFeature(VaultSession.INSTANCE));

        // Future features can be added here:
        // registry.register(new EncryptFileFeature(VaultSession.INSTANCE));
        // registry.register(new DecryptFileFeature(VaultSession.INSTANCE));
        // registry.register(new HideInImageFeature(VaultSession.INSTANCE));
        // registry.register(new ManagePasswordsFeature(VaultSession.INSTANCE));
        // registry.register(new GeneratePasswordFeature());
        // registry.register(new ChangeSecurityProfileFeature(VaultSession.INSTANCE));
        // registry.register(new BackupVaultFeature(VaultStorage.INSTANCE));
    }
}