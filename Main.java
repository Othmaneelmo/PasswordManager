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

      // Very small built-in blacklist; later you can swap for a file-based list.
      private static final char[][] BLACKLIST = new char[][]{
        "password".toCharArray(),
        "qwerty".toCharArray(),
        "letmein".toCharArray(),
        "welcome".toCharArray(),
        "admin".toCharArray(),
        "12345678".toCharArray()
      };

      private static boolean equalsIgnoreCase(char[] a, char[] b) {
        if (a.length != b.length) return false;
        for (int i = 0; i < a.length; i++) {
          if (Character.toLowerCase(a[i]) != Character.toLowerCase(b[i])) return false;
        }
        return true;
      }

            private static int countUniquesAsciiBuckets(char[] pwd) {
        boolean[] seen = new boolean[256]; // small, avoids allocations of Collections
        int u = 0;
        for (char c : pwd) {
          int idx = (c & 0xFF);
          if (!seen[idx]) { seen[idx] = true; u++; }
        }
        return u;
      }

      private static boolean hasSimpleAscendingSequence(char[] pwd, int win) {
        if (pwd.length < win) return false;
        // Work on a lowercased copy to be case-insensitive
        char[] lc = Arrays.copyOf(pwd, pwd.length);
        for (int i = 0; i < lc.length; i++) lc[i] = Character.toLowerCase(lc[i]);

        boolean hit = false;
        int streak = 1;
        for (int i = 1; i < lc.length; i++) {
          if (lc[i] == lc[i - 1] + 1) {
            streak++;
            if (streak >= win) { hit = true; break; }
          } else {
            streak = 1;
          }
        }
        // zeroize the temp copy
        Arrays.fill(lc, '\0');
        return hit;
      }

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
        
        // whitespace / control characters + leading/trailing spaces
        if (Character.isWhitespace(pwd[0]) || Character.isWhitespace(pwd[pwd.length - 1])) {
          reasons.add("cannot start or end with whitespace");
        }
        for (char c : pwd) {
          if (Character.isWhitespace(c) || Character.isISOControl(c)) {
            reasons.add("cannot contain whitespace or control characters");
            break;
          }
        }

        // no more than 2 identical characters in a row
        int run = 1;
        for (int i = 1; i < pwd.length; i++) {
          run = (pwd[i] == pwd[i - 1]) ? run + 1 : 1;
          if (run > 2) {
            reasons.add("cannot have more than 2 identical characters in a row");
            break;
          }
        }

        // uniqueness
        int unique = countUniquesAsciiBuckets(pwd);
        if (unique < 5) {
          reasons.add("must contain at least 5 different characters");
        }

        // simple sequences like abcd or 1234 (length >= 4)
        if (hasSimpleAscendingSequence(pwd, 4)) {
          reasons.add("cannot contain simple ascending sequences of length 4 or more");
        }

        // blacklist (case-insensitive, without creating Strings)
        for (char[] bad : BLACKLIST) {
          if (equalsIgnoreCase(pwd, bad)) {
            reasons.add("is too common (appears on common-password lists)");
            break;
          }
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