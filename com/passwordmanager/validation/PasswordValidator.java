package com.passwordmanager.validation;
/*TODO:
this should probably be reworked, since were working on the MASTER KEY complexity checker. not random password.
BUT, i would leave this for now since it should not stop or slow making the other essential features for the password manager.
here are things that should be implemented:
-  minimum 16 chars, 24+ if using passphrases (white space, no symbols), (passphrases are encouraged, 7+ words i suppose)
-  Character diversity (if not a passphrase)
        - At least one uppercase letter (A–Z)
        - At least one lowercase letter (a–z)
        - At least one digit (0–9)
        - At least one special character from a broad set (not just !@#$%)
        - No restriction on repeated characters — repetition isn’t inherently weak if length is good.
-  Blacklist weak patterns
        - Disallow passwords in common breach lists (check against a Have I Been Pwned database). (API MAYBE??)
        - Disallow obvious sequences like 123456, abcdef, keyboard walks (qwertyui), or simple substitutions (P@ssw0rd).

-  Unicode & space support
        - Support spaces so users can make easy-to-remember passphrases.
        - Allow Unicode characters (but watch for normalization issues — store them in a canonical form like NFC).

---------------------------------------------------------------------------------------------------------------------------
FOLLOWING are CHATGPT recommmendation (check for validity later):
-  Rate-limiting and offline resistance
        - Even with strong rules, implement slow hashing (e.g., Argon2id with high memory cost) so brute force attempts are impractical.
        - Rate-limit and lockout for online entry attempts.

-  No arbitrary "max length" unless necessary
        - Many breaches happen because developers truncate or mishandle long passwords.
        - Support at least 128 characters to future-proof.

-  Educate instead of frustrate
        - Don’t just reject a password — explain why it’s weak and show examples of better ones.
        - If you support passphrases, make that clear in the UI (""A long phrase like ‘correct horse battery staple lamp’ is stronger than P@ssw0rd1!").

-  Avoid forced regular changes
        - For a master key, forcing users to change it every X days leads to weaker, easier-to-remember passwords.
        - Instead, require change only if it’s compromised.

-  Encourage a secure backup method
        - Users might forget a 24-character passphrase.
        - Provide a secure recovery key or offline backup method (encrypted & stored safely) instead of weaker recovery questions.

-  No predictable truncation or hashing quirks
        - If your backend only stores the first N bytes for some reason, an attacker could exploit that.
        - Always hash the entire master key with something like Argon2id and never truncate before hashing.

-  Entropy measurement, not just pattern rules
        - Two passwords can meet all "has uppercase, lowercase, number, special" rules and still be weak (P@ssw0rd123!).
        - Use an entropy estimator (like zxcvbn) to reject anything with estimated crack time < ~10^14 guesses.

-  Handle copy-paste correctly
        - Don’t disable paste into the password field — it allows password managers to fill long keys.
        - Just protect against clipboard leaks.

-  Make typos harder to cause lockout
        - Consider allowing a small number of retry attempts before exponential lockout.
        - Warn if Caps Lock is on or if there are leading/trailing spaces.

-  Secure transport from client to server
        - Even the strongest master key is useless if it’s sent in plaintext or logged.
        - Use TLS, avoid logging input, and sanitize all storage paths.
*/


/*
TL;DR: 
 *Validates passwords without creating Strings (works on char[] directly).
 * 
 * Checks performed:
 *  - Minimum length: 12 characters
 *  - Must include at least 3 of: lowercase, uppercase, digit, symbol
 *  - Cannot start or end with whitespace
 *  - Cannot contain whitespace or control characters
 *  - Must have ≥ 5 unique characters
 *  - Cannot contain simple ascending sequences (≥ 4 chars, case-insensitive)
 *  - Rejects exact matches from a small built-in blacklist
 * 
 * Returns ValidationResult with pass/fail status and reasons list.
 * 
 * Design notes:
 *  - Incremental design: future commits add more checks without changing existing code
 *  - No String allocation → minimizes GC overhead & improves security (avoids lingering copies)
 */
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

      public static ValidationResult validate(char[] pwd) {
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

/*  
//WHAT THE FUCK IS THIS, 
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