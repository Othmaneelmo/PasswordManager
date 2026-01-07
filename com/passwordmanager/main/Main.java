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
  public static void main(String[] args) {
    try {
/*
    using char array then converting to string because:
        - String are immutable, they are saved in memory
        - can be hacked (memory dump) before java garbage collector removes it
    Using console and not scanner because:
        - Scanner shows password when typed
*/
    Console console = System.console();
    if (console == null) {
      System.out.println("Console unavailable. Please run in a terminal environment.");
      return;
    }

    char[] masterKeyChars = console.readPassword("Create a Master key: ");


//PASSWORD VALIDATION:
/* 
* This prints out whether the inputted password was valid or not, with a list of reason why not:
*  - it takes masterKeyChars (char[]) as a parameter, 
*  - PasswordValidator.validate() method checks for password complexity, and add reason X if rule Y is not respected
*  - PasswordValidator.validate() method returns ValidationResult(reasons.isEmpty(), reasons)
*  - the latter ValidationResult() returns whether the passowrd is valid (boolean ok), and the reasons (List<String> messages)
*  - from the above return statements, this code section below prints appropriate messages(according to the return stats), AND CLEARS THE INVALID PASSWORD (char[])
*/
    ValidationResult vr = PasswordValidator.validate(masterKeyChars);
    if (!vr.ok()) {
      System.out.println("Password not strong enough:");
      for (String msg : vr.messages()){
        System.out.println(" - " + msg);
      }
      Arrays.fill(masterKeyChars, ' '); // clear array before exiting
      return;
    }
/*In case we dont use default parameters
 *  int iterations = 600_000;   // high iteration count
    byte[] salt = PBKDF2Hasher.generateSalt();
    String encodedSalt = Base64.getEncoder().encodeToString(salt);
*/


        
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
