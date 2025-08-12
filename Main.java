/*TODO
 * 1. Avoid converting the password to a String — Keep it as a char[] to improve security.
 * 2. Clear the password array after use to avoid it lingering in memory.
 * 3. Add password validation (e.g., length, complexity).
 * 4. Use the master key for something meaningful, like encryption or authentication.
 * 5. Implement functionality to store or verify the master key safely.
 * 6. Handle exceptions and edge cases gracefully.
 * 
 */

import java.io.Console;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.list;
import java.util.ArrayList;

public class Main {
  public static void main(String[] args) {
    Console console = System.console();

    if (console == null) {
      System.out.println("console not working, use a terminal!");
      return;
    }
    /*
    using char array then converting to string because:
        -String are immutable, they are saved in memory
        -can be hacked (memory dump) before java garbage collector removes it
    Using console and not scanner because:
        -Scanner shows password when typed
    */
    char[] masterKeyChars = console.readPassword("Create a Master key: ");

    //Simple length validation for passoword (>8), NEEDS UPGRADE
    if (masterKeyChars.length < 8) {
      System.out.println("Password too short. Must be at least 8 characters.");
      Arrays.fill(masterKeyChars, ' '); //clear array
    return;
    }

    /* UPGRADE: advanced password validation (keeps char[]; no String)
     * - At least 12 chars (additive to the 8+ check above)
     * - At least 3 of 4 classes: lower / upper / digit / symbol
     * - No String allocations for the password (security)
     */
    PasswordValidator.ValidationResult vr = PasswordValidator.validate(masterKeyChars);
    if (!vr.ok()) {
      System.out.println("Password not strong enough:");
      for (String msg : vr.messages()) System.out.println(" - " + msg);
      Arrays.fill(masterKeyChars, ' '); // clear array before exiting
      return;
    }

    //Converting Masterkey char[] to byte[] (for MessageDigest API)
    // Convert char[] to byte[] manually (2 bytes per char)
    byte[] masterKeyBytes = new byte[masterKeyChars.length * 2];
    for (int i = 0; i < masterKeyChars.length; i++) {
        masterKeyBytes[i * 2] = (byte) (masterKeyChars[i] >> 8); //high byte
        masterKeyBytes[i * 2 + 1] = (byte) masterKeyChars[i]; //low byte
    }
    // Clear char[] asap
    Arrays.fill(masterKeyChars, ' ');

    byte[] hashedKey = null; // declare outside try

    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      hashedKey = digest.digest(masterKeyBytes);
      Arrays.fill(masterKeyBytes, (byte) 0);
      
    } catch (NoSuchAlgorithmException e) {
      System.out.println("SHA-256 algorithm not available. Exiting...");
      Arrays.fill(masterKeyChars, ' ');  // Clear password on error too
      return;
    }
    
  }
      /* ---------------- Password Validator (incremental, no Strings) ----------------
     * Phase 1 (this commit): min length + character classes.
     * More checks will be added in later commits without changing existing code.
     */
    static final class PasswordValidator {
      private static final int MIN_LENGTH = 12; // additive to your 8+ precheck

      static ValidationResult validate(char[] pwd) {
        List<String> reasons = new ArrayList<>();
        if (pwd == null || pwd.length == 0) {
          reasons.add("cannot be empty");
          return new ValidationResult(false, reasons);
        }

        // length
        if (pwd.length < MIN_LENGTH) {
          reasons.add("must be at least " + MIN_LENGTH + " characters long");
        }

        // character classes
        boolean hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false;
        for (char c : pwd) {
          if (c >= 'a' && c <= 'z') hasLower = true;
          else if (c >= 'A' && c <= 'Z') hasUpper = true;
          else if (c >= '0' && c <= '9') hasDigit = true;
          else hasSymbol = true;
        }
        int classes = (hasLower?1:0) + (hasUpper?1:0) + (hasDigit?1:0) + (hasSymbol?1:0);
        if (classes < 3) {
          reasons.add("must include at least 3 of: lowercase, uppercase, digit, symbol");
        }

        return new ValidationResult(reasons.isEmpty(), reasons);
      }

      /* Simple container so we can add more detail later */
      static final class ValidationResult {
        private final boolean ok;
        private final List<String> messages;
        ValidationResult(boolean ok, List<String> messages) { this.ok = ok; this.messages = messages; }
        boolean ok() { return ok; }
        List<String> messages() { return messages; }
      }
    }
}
/*this is a test for the commits you see */