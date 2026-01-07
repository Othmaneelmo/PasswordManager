package com.passwordmanager.main;

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
 * Main entry point for the Vault application.
 * <p>
 * Handles creation and verification of the master key using PBKDF2 hashing,
 * and manages unlocking the vault session.
 * </p>
 * <p>
 * Passwords are handled as {@code char[]} arrays to reduce memory exposure,
 * and are cleared from memory immediately after use.
 * </p>
 */
public class Main {
    /**
     * Application entry point.
     * <p>
     * Prompts the user to create a master key, validates it, hashes it using PBKDF2,
     * stores it securely, and allows verification to unlock the vault session.
     * </p>
     *
     * @param args Command-line arguments (ignored)
     * @throws IOException If reading or writing vault storage fails
     */
    public static void main(String[] args) throws IOException {
        Console console = System.console();
        if (console == null) {
            System.out.println("Console unavailable. Please run in a terminal environment.");
            return;
        }

        char[] masterKeyChars = console.readPassword("Create a Master key: ");

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
            Arrays.fill(masterKeyChars, ' '); // ensures cleanup in all cases
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

                // Ask user to re-enter master key for verification
                char[] masterKeyVerification = console.readPassword("Re-enter the master key to unlock: ");

                boolean verified = PBKDF2Hasher.verifyPassword(masterKeyVerification, stored);

        if(sameMasterKey){
          System.out.println("same masterKey inputted: Good!");
          byte[] sessionKey = PBKDF2Hasher.deriveKey(masterKeyVerification, stored);
          VaultSession.unlock(sessionKey);
          Arrays.fill(sessionKey, (byte) 0); // clear temp copy
          System.out.println("Vault is now unlocked!");
        }else{
          System.out.println("Wrong masterKey, or Something went Wrong!");
        }
        Arrays.fill(masterKeyVerification, ' ');  //cleanUp
      
      }catch(IOException IOErr){
        System.out.println("Error reading vault: " + IOErr.getMessage());
      }catch(NoSuchAlgorithmException algoErr){
        System.out.println("Cannot find Used Algorithm: " + algoErr.getMessage());
      }catch(InvalidKeySpecException keySpecErr){
        System.out.println("Key Spec error: " + keySpecErr.getMessage());
      }
    }

  }
}
