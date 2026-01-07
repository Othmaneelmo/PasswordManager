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

        
    try {
        HashedPassword encodedHash = PBKDF2Hasher.defaultHashPassword(masterKeyChars);

        /*TODO: store hash + encodedsalt + iterations securely*/

        if (!VaultStorage.exists()) {
            VaultStorage.saveMasterKey(encodedHash.getAlgorithm(), encodedHash.getIterations(), encodedHash.getSalt(), encodedHash.getHash());
            System.out.println("Master key saved to vault!");
        } else {
          //below overwrites masterkey.json, current raw masterkey: password123@
            //VaultStorage.saveMasterKey(encodedHash.getAlgorithm(), encodedHash.getIterations(), encodedHash.getSalt(), encodedHash.getHash());
            //System.out.println("Master key saved to vault!");
            System.out.println("Master key already exists — not overwriting.");
        }

    } catch (NoSuchAlgorithmException e) {
        System.out.println("PBKDF2 algorithm not available: " + e.getMessage());
    } catch (InvalidKeySpecException e) {
        System.out.println("Invalid PBKDF2 key specification: " + e.getMessage());
    } finally {
        Arrays.fill(masterKeyChars, ' '); // ensures cleanup in all cases
    }
    
    
    //Test: load and verify masterkey
    if(VaultStorage.exists()){
      System.out.println("Testing masterkey Loading and Verification");
      try{
        //Load JSON and parse it into HashedPassword
        HashedPassword stored = VaultStorage.loadHashedPassword();

        //Ask user to reenter masterkey for verifying
        char[] masterKeyVerification = console.readPassword("Re-enter the masterkey: ");
        
        boolean sameMasterKey = PBKDF2Hasher.verifyPassword(masterKeyVerification, stored);

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
