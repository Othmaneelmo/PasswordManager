
/* KEEP IN MIND
 * 1. Avoid converting the password to a String — Keep it as a char[] to improve security.
 * 2. Clear the password array after use to avoid it lingering in memory.
*/
/* TODO (Project Security Plan):
 *
 * 1. Replace plain SHA-256 with PBKDF2:
 *    - Use javax.crypto.SecretKeyFactory with "PBKDF2WithHmacSHA256".
 *    - Use a random salt (16–32 bytes) for each password.
 *    - Use a high iteration count (e.g., ~600,000) for better security.
 *    - Store: hash + salt + iteration count.
 *    - Use SecureRandom for generating salts.
 *
 * 2. Implement password verification:
 *    - On login, load salt + iteration count + hash from storage.
 *    - Run PBKDF2 with the same parameters on the entered password.
 *    - Compare results securely (constant-time).
 *    - Keep derived encryption key only in memory after unlock.
 *
 * 3. Update storage format:
 *    - Save hash, salt, iteration count per master key.
 *    - Store encrypted account passwords (AES-GCM recommended) with IVs.
 *    - Consider a formatVersion/algorithmVersion field for future upgrades.
 *
 * 4. Add CLI menu (top-level interface):
 *        [1] Set/Reset Master Key       # Create or change the vault's master key
 *        [2] Unlock Vault               # Authenticate to access stored passwords
 *        [3] Add Account Password       # Store account name + password (encrypted)
 *        [4] List Accounts              # Show saved account names (but not passwords)
 *        [5] Retrieve Account Password  # Decrypt & show password for chosen account
 *        [6] Encrypt a File             # Bonus: encrypt file with derived key
 *        [7] Decrypt a File             # Bonus: decrypt file with derived key
 *        [0] Exit
 *
 * 5. Project structure / utilities:
 *    - Keep crypto logic in separate classes (PasswordHasher, VaultStorage, CryptoUtils).
 *    - Plan storage location (file, JSON, or SQLite) for hashes + encrypted data.
 *    - Ensure secure random generation for salts, IVs, etc.
 *
 * 6. Testing:
 *    - Verify password hashing and verification.
 *    - Verify encryption/decryption of account passwords and files.
 *    - Test edge cases (empty/long passwords, invalid input).
 *    - Ensure login/unlock is reasonably fast (< 1 second).
 *
 * 7. Logging / safety:
 *    - Do not log sensitive data (plaintext passwords, keys, hashes).
 *    - Use logging only for general program flow/debug info.
 *
 * Note: PBKDF2 is secure enough for this learning project. No need to add Argon2 or other KDFs.
 */


import java.io.Console;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Main {
  public static void main(String[] args) throws IOException {
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

    //Check if vaultStorage exists
//    if (VaultStorage.exists()) {
//      return;
//    }
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

    // --- PBKDF2 placeholders ---
    SecureRandom saltGenerator = new SecureRandom();
    byte[] salt = new byte[16]; // 16 bytes = 128 bits
    saltGenerator.nextBytes(salt);
    // Encode salt in Base64 for storage
    String encodedSalt = Base64.getEncoder().encodeToString(salt);
    int iterations = 600_000;   // high iteration count
    int keyLength = 256;        // key length in bit
      
    try {
        // Create PBEKeySpec with char[] password, salt, iterations, key length
        PBEKeySpec spec = new PBEKeySpec(masterKeyChars, salt, iterations, keyLength);

        // Generate the PBKDF2 hash
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hash = skf.generateSecret(spec).getEncoded();

        // Clear the password inside PBEKeySpec
        spec.clearPassword();
        // Encode hash in Base64 for storage
        String encodedHash = Base64.getEncoder().encodeToString(hash);


        // Store as algorithm:iterations:salt:hash
        String stored = "PBKDF2WithHmacSHA256" + ":" 
                      + iterations + ":" 
                      + encodedSalt + ":" 
                      + encodedHash;
        //remove this when done
        System.out.println("PBKDF2 hash generated and stored:");
        System.out.println(stored);
      
        /*TODO: store hash + encodedsalt + iterations securely*/
        System.out.println("PBKDF2 hash generated successfully!");

        
        if (!VaultStorage.exists()) {   // Save only if file doesn’t already exist
            VaultStorage.saveMasterKey("PBKDF2WithHmacSHA256", iterations, encodedSalt, encodedHash);
            System.out.println("Master key saved to vault!");
        } else {
          VaultStorage.saveMasterKey("PBKDF2WithHmacSHA256", iterations, encodedSalt, encodedHash);
          System.out.println("Master key saved to vault!");
          //in case we DONt want to overwrite ---> will decide.
          // System.out.println("Master key already exists — not overwriting.");
        }

        
    } catch (NoSuchAlgorithmException e) {
    System.out.println("PBKDF2 algorithm not available: " + e.getMessage());
    } catch (InvalidKeySpecException e) {
    System.out.println("Invalid PBKDF2 key specification: " + e.getMessage());

    }finally {
    Arrays.fill(masterKeyChars, ' '); // ensures cleanup in all cases
    }



  }
}
