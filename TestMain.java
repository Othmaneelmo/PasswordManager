import com.passwordmanager.security.HashedPassword;
import com.passwordmanager.security.PBKDF2Hasher;
import com.passwordmanager.storage.VaultSession;
import com.passwordmanager.storage.VaultStorage;
import com.passwordmanager.validation.PasswordValidator;
import com.passwordmanager.validation.ValidationResult;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Test version of Main.java that accepts password as command-line argument for testing.
 */
public class TestMain {
    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            System.out.println("Usage: java TestMain <password>");
            return;
        }

        char[] masterKeyChars = args[0].toCharArray();

        // PASSWORD VALIDATION
        ValidationResult vr = PasswordValidator.validate(masterKeyChars);
        if (!vr.ok()) {
            System.out.println("Password not strong enough:");
            for (String msg : vr.messages()) {
                System.out.println(" - " + msg);
            }
            Arrays.fill(masterKeyChars, ' ');
            return;
        }

        // HASH PASSWORD FOR AUTHENTICATION
        try {
            HashedPassword encodedHash = PBKDF2Hasher.defaultHashPassword(masterKeyChars);

            System.out.println("PBKDF2 hash generated successfully!");

            // SAVE TO VAULT (if not exists)
            if (!VaultStorage.exists()) {
                VaultStorage.saveMasterKey(
                    encodedHash.getAlgorithm(),
                    encodedHash.getIterations(),
                    encodedHash.getSalt(),
                    encodedHash.getHash()
                );
                System.out.println("Master key saved to vault!");
            } else {
                System.out.println("Master key already exists — not overwriting.");
            }

        } catch (NoSuchAlgorithmException e) {
            System.out.println("PBKDF2 algorithm not available: " + e.getMessage());
            Arrays.fill(masterKeyChars, ' ');
            return;
        } catch (InvalidKeySpecException e) {
            System.out.println("Invalid PBKDF2 key specification: " + e.getMessage());
            Arrays.fill(masterKeyChars, ' ');
            return;
        } finally {
            Arrays.fill(masterKeyChars, ' ');
        }

        // LOAD AND VERIFY MASTER KEY
        if (VaultStorage.exists()) {
            System.out.println("\n--- Vault Unlock Test ---");
            try {
                // Load stored hash
                HashedPassword stored = VaultStorage.loadHashedPassword();
                if (stored == null) {
                    System.out.println("Error: Could not load master key from vault.");
                    return;
                }

                // Use the same password for verification
                char[] masterKeyVerification = args[0].toCharArray();

                boolean verified = PBKDF2Hasher.verifyPassword(masterKeyVerification, stored);

                if (verified) {
                    System.out.println("✓ Master key verified!");

                    // Derive session key and unlock vault
                    byte[] sessionKey = PBKDF2Hasher.deriveSessionKey(masterKeyVerification, stored);

                    try {
                        VaultSession.unlock(sessionKey);
                        System.out.println("✓ Vault is now unlocked! State: " + VaultSession.getState());

                        // Demonstrate that we can access the session key
                        if (VaultSession.isUnlocked()) {
                            System.out.println("✓ Session key is accessible for cryptographic operations.");
                        }

                        // Lock the vault when done
                        VaultSession.lock();
                        System.out.println("✓ Vault locked. State: " + VaultSession.getState());

                    } finally {
                        // Always zeroize session key
                        Arrays.fill(sessionKey, (byte) 0);
                    }

                } else {
                    System.out.println("✗ Wrong master key!");
                }

                Arrays.fill(masterKeyVerification, ' ');

            } catch (IOException ioErr) {
                System.out.println("Error reading vault: " + ioErr.getMessage());
            } catch (NoSuchAlgorithmException algoErr) {
                System.out.println("Cannot find used algorithm: " + algoErr.getMessage());
            } catch (InvalidKeySpecException keySpecErr) {
                System.out.println("Key spec error: " + keySpecErr.getMessage());
            } catch (IllegalStateException stateErr) {
                System.out.println("Vault state error: " + stateErr.getMessage());
            }
        }
    }
}
