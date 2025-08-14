import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

      /* ---------------- Password Validator (incremental, no Strings) ----------------
     * Phase 1 (this commit): min length + character classes.
     * More checks will be added in later commits without changing existing code.
     */
    public final class PasswordValidator {
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
        }//i dont understand why not allow whitespace in middle of password
/*  //WHAT THE FUCK IS THIS, 
    //maybe stop user from inputing password made of only 3 identical characters or sum (aaabbbccc),
    // but "thisisAgOOdPassword123@" wouldnt work because of "OO" and "ss"

    
        // no more than 2 identical characters in a row
        int run = 1;
        for (int i = 1; i < pwd.length; i++) {
          run = (pwd[i] == pwd[i - 1]) ? run + 1 : 1;
          if (run > 2) {
            reasons.add("cannot have more than 2 identical characters in a row");
            break;
          }
        }
*/
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


}