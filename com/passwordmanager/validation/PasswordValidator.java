package com.passwordmanager.validation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Validates master passwords/passphrases without creating Strings (works on char[] directly).
 * <p>
 * <b>Validation Strategy:</b>
 * </p>
 * <ul>
 *   <li>Supports both traditional passwords AND passphrases</li>
 *   <li>Passphrases: 16+ characters, can contain spaces, more forgiving on character classes</li>
 *   <li>Traditional passwords: 12+ characters, stricter character class requirements</li>
 * </ul>
 * 
 * <p><b>Checks Performed:</b></p>
 * <ul>
 *   <li>Minimum length: 12 characters (16+ recommended for passphrases)</li>
 *   <li>For traditional passwords (no spaces): Must include at least 3 of: lowercase, uppercase, digit, symbol</li>
 *   <li>For passphrases (with spaces): More lenient character requirements</li>
 *   <li>Cannot start or end with whitespace</li>
 *   <li>Must have ≥ 5 unique characters</li>
 *   <li>Cannot contain simple ascending sequences (≥ 4 chars, case-insensitive)</li>
 *   <li>Rejects exact matches from a small built-in blacklist</li>
 * </ul>
 * 
 * <p><b>Design Notes:</b></p>
 * <ul>
 *   <li>No String allocation → minimizes GC overhead & improves security (avoids lingering copies)</li>
 *   <li>Encourages passphrases for better memorability and security</li>
 *   <li>Returns ValidationResult with pass/fail status and detailed reasons</li>
 * </ul>
 * 
 * <p><b>TODO (Future Improvements):</b></p>
 * <ul>
 *   <li>Add breach database checking (Have I Been Pwned API)</li>
 *   <li>Entropy estimation (zxcvbn-style)</li>
 *   <li>Keyboard pattern detection (qwertyui, asdfgh)</li>
 *   <li>Unicode normalization support</li>
 *   <li>Configurable minimum lengths per use case</li>
 * </ul>
 */
public final class PasswordValidator {
    private static final int MIN_LENGTH = 12;
    private static final int RECOMMENDED_PASSPHRASE_LENGTH = 16;

    // Very small built-in blacklist; later you can swap for a file-based list.
    private static final char[][] BLACKLIST = new char[][]{
        "password".toCharArray(),
        "qwerty".toCharArray(),
        "letmein".toCharArray(),
        "welcome".toCharArray(),
        "admin".toCharArray(),
        "12345678".toCharArray()
    };

    private PasswordValidator() {
        throw new AssertionError("Utility class");
    }

    /**
     * Validates a master password or passphrase.
     * <p>
     * Automatically detects whether input is a traditional password or passphrase
     * based on the presence of internal spaces.
     * </p>
     *
     * @param pwd the password/passphrase to validate
     * @return ValidationResult with pass/fail status and detailed reasons
     */
    public static ValidationResult validate(char[] pwd) {
        List<String> reasons = new ArrayList<>();
        if (pwd == null || pwd.length == 0) {
            reasons.add("cannot be empty");
            return new ValidationResult(false, reasons);
        }

        // Detect if this is a passphrase (contains internal spaces)
        boolean isPassphrase = containsInternalSpaces(pwd);

        // Length validation
        if (pwd.length < MIN_LENGTH) {
            reasons.add("must be at least " + MIN_LENGTH + " characters long");
        }
        
        if (isPassphrase && pwd.length < RECOMMENDED_PASSPHRASE_LENGTH) {
            reasons.add("passphrases should be at least " + RECOMMENDED_PASSPHRASE_LENGTH + 
                       " characters for better security");
        }

        // Leading/trailing whitespace check
        if (Character.isWhitespace(pwd[0]) || Character.isWhitespace(pwd[pwd.length - 1])) {
            reasons.add("cannot start or end with whitespace");
        }

        // Control characters check (but allow internal spaces for passphrases)
        for (char c : pwd) {
            if (Character.isISOControl(c)) {
                reasons.add("cannot contain control characters");
                break;
            }
        }

        // Character class validation
        if (isPassphrase) {
            validatePassphrase(pwd, reasons);
        } else {
            validateTraditionalPassword(pwd, reasons);
        }

        // Uniqueness check
        int unique = countUniquesAsciiBuckets(pwd);
        if (unique < 5) {
            reasons.add("must contain at least 5 different characters");
        }

        // Simple sequence detection
        if (hasSimpleAscendingSequence(pwd, 4)) {
            reasons.add("cannot contain simple ascending sequences of length 4 or more (e.g., 'abcd', '1234')");
        }

        // Blacklist check
        for (char[] bad : BLACKLIST) {
            if (equalsIgnoreCase(pwd, bad)) {
                reasons.add("is too common (appears on common-password lists)");
                break;
            }
        }

        return new ValidationResult(reasons.isEmpty(), reasons);
    }

    /**
     * Validates a traditional password (no internal spaces).
     * Requires at least 3 character classes.
     */
    private static void validateTraditionalPassword(char[] pwd, List<String> reasons) {
        boolean hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false;
        
        for (char c : pwd) {
            if (c >= 'a' && c <= 'z') hasLower = true;
            else if (c >= 'A' && c <= 'Z') hasUpper = true;
            else if (c >= '0' && c <= '9') hasDigit = true;
            else if (!Character.isWhitespace(c)) hasSymbol = true;
        }
        
        int classes = (hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + 
                     (hasDigit ? 1 : 0) + (hasSymbol ? 1 : 0);
        
        if (classes < 3) {
            reasons.add("must include at least 3 of: lowercase, uppercase, digit, symbol");
        }
    }

    /**
     * Validates a passphrase (contains internal spaces).
     * More lenient - just needs some character diversity.
     */
    private static void validatePassphrase(char[] pwd, List<String> reasons) {
        boolean hasLetter = false;
        boolean hasOther = false;
        
        for (char c : pwd) {
            if (Character.isLetter(c)) {
                hasLetter = true;
            } else if (!Character.isWhitespace(c)) {
                hasOther = true;
            }
        }
        
        if (!hasLetter) {
            reasons.add("passphrase must contain at least some letters");
        }
        
        // For very long passphrases, we're more forgiving
        if (pwd.length < 20 && !hasOther) {
            reasons.add("passphrase should include numbers or symbols for better security");
        }
    }

    /**
     * Checks if password contains internal spaces (indicates passphrase).
     */
    private static boolean containsInternalSpaces(char[] pwd) {
        // Check for spaces that are not at the beginning or end
        for (int i = 1; i < pwd.length - 1; i++) {
            if (pwd[i] == ' ') {
                return true;
            }
        }
        return false;
    }

    /**
     * Case-insensitive equality check without creating Strings.
     */
    private static boolean equalsIgnoreCase(char[] a, char[] b) {
        if (a.length != b.length) return false;
        for (int i = 0; i < a.length; i++) {
            if (Character.toLowerCase(a[i]) != Character.toLowerCase(b[i])) return false;
        }
        return true;
    }

    /**
     * Counts unique characters using ASCII buckets (no Collections needed).
     */
    private static int countUniquesAsciiBuckets(char[] pwd) {
        boolean[] seen = new boolean[256];
        int u = 0;
        for (char c : pwd) {
            int idx = (c & 0xFF);
            if (!seen[idx]) { 
                seen[idx] = true; 
                u++; 
            }
        }
        return u;
    }

    /**
     * Detects simple ascending sequences (case-insensitive).
     * Example: "abcd", "1234", "WXYZ"
     */
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
                if (streak >= win) { 
                    hit = true; 
                    break; 
                }
            } else {
                streak = 1;
            }
        }
        
        // Zeroize the temp copy
        Arrays.fill(lc, '\0');
        return hit;
    }
}