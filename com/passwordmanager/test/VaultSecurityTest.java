package com.passwordmanager.test;

import com.passwordmanager.security.HashedPassword;
import com.passwordmanager.security.PBKDF2Hasher;
import com.passwordmanager.storage.VaultSession;
import com.passwordmanager.storage.VaultStorage;
import java.util.Arrays;
import java.util.Base64;

/**
 * Advanced test suite for the password manager vault core.
 */
public class VaultSecurityTest {

    private static int testsRun = 0;
    private static int testsPassed = 0;
    private static int testsFailed = 0;

    public static void main(String[] args) {
        System.out.println("=".repeat(80));
        System.out.println("VAULT SECURITY TEST SUITE");
        System.out.println("=".repeat(80));
        System.out.println();

        cleanupVault();

        runCryptographicTests();
        runMemorySafetyTests();

        System.out.println();
        System.out.println("=".repeat(80));
        System.out.println("TEST SUMMARY");
        System.out.println("=".repeat(80));
        System.out.println("Total tests run: " + testsRun);
        System.out.println("Passed: " + testsPassed);
        System.out.println("Failed: " + testsFailed);
    }

    private static void runCryptographicTests() {
        printCategory("CRYPTOGRAPHIC CORRECTNESS");

        test("Hash determinism", () -> {
            char[] pwd = "test123@ABC".toCharArray();
            byte[] salt = PBKDF2Hasher.generateSalt();

            HashedPassword h1 = PBKDF2Hasher.hashPassword(pwd, salt, 100000);
            HashedPassword h2 = PBKDF2Hasher.hashPassword(pwd, salt, 100000);

            assertTrue(h1.getHash().equals(h2.getHash()),
                    "Same password + salt + iterations should produce identical hash");

            Arrays.fill(pwd, ' ');
        });

        test("Salt uniqueness", () -> {
            byte[] salt1 = PBKDF2Hasher.generateSalt();
            byte[] salt2 = PBKDF2Hasher.generateSalt();

            assertFalse(Arrays.equals(salt1, salt2),
                    "Two generated salts should be different");
        });

        test("Different salts produce different hashes", () -> {
            char[] pwd = "samePassword".toCharArray();
            byte[] salt1 = PBKDF2Hasher.generateSalt();
            byte[] salt2 = PBKDF2Hasher.generateSalt();
            
            HashedPassword h1 = PBKDF2Hasher.hashPassword(pwd, salt1, 100000);
            HashedPassword h2 = PBKDF2Hasher.hashPassword(pwd, salt2, 100000);
            
            assertFalse(h1.getHash().equals(h2.getHash()), 
                "Different salts should produce different hashes");
            Arrays.fill(pwd, ' ');
        });

                test("Password verification - correct password", () -> {
            char[] pwd = "correctPassword123!".toCharArray();
            HashedPassword stored = PBKDF2Hasher.defaultHashPassword(pwd);
            
            boolean verified = PBKDF2Hasher.verifyPassword(pwd, stored);
            
            assertTrue(verified, "Correct password should verify successfully");
            Arrays.fill(pwd, ' ');
        });
        test("Password verification - incorrect password", () -> {
            char[] pwd = "correctPassword123!".toCharArray();
            HashedPassword stored = PBKDF2Hasher.defaultHashPassword(pwd);
            Arrays.fill(pwd, ' ');
            
            char[] wrong = "wrongPassword456!".toCharArray();
            boolean verified = PBKDF2Hasher.verifyPassword(wrong, stored);
            
            assertFalse(verified, "Wrong password should fail verification");
            Arrays.fill(wrong, ' ');
        });
        test("Session key derivation consistency", () -> {
            char[] pwd = "sessionKeyTest".toCharArray();
            HashedPassword stored = PBKDF2Hasher.defaultHashPassword(pwd);
            
            byte[] key1 = PBKDF2Hasher.deriveSessionKey(pwd, stored);
            byte[] key2 = PBKDF2Hasher.deriveSessionKey(pwd, stored);
            
            assertTrue(Arrays.equals(key1, key2), 
                "Same password should derive identical session keys");
            
            Arrays.fill(pwd, ' ');
            Arrays.fill(key1, (byte) 0);
            Arrays.fill(key2, (byte) 0);
        });

        test("Session key is 256 bits", () -> {
            char[] pwd = "keyLengthTest".toCharArray();
            HashedPassword stored = PBKDF2Hasher.defaultHashPassword(pwd);
            
            byte[] key = PBKDF2Hasher.deriveSessionKey(pwd, stored);
            
            assertEquals(32, key.length, "Session key should be 32 bytes (256 bits)");
            
            Arrays.fill(pwd, ' ');
            Arrays.fill(key, (byte) 0);
        });
                test("Hash output is Base64 encoded", () -> {
            char[] pwd = "base64Test".toCharArray();
            HashedPassword stored = PBKDF2Hasher.defaultHashPassword(pwd);
            
            try {
                byte[] decoded = Base64.getDecoder().decode(stored.getHash());
                assertEquals(32, decoded.length, "Decoded hash should be 32 bytes");
            } catch (IllegalArgumentException e) {
                fail("Hash should be valid Base64");
            }
            
            Arrays.fill(pwd, ' ');
        });
    }
    // ==================== MEMORY SAFETY TESTS ====================

    private static void runMemorySafetyTests() {
        printCategory("MEMORY SAFETY");
    
    }
    private static void test(String name, TestRunnable runnable) {
        testsRun++;
        System.out.print("  [" + testsRun + "] " + name + " ... ");

        try {
            runnable.run();
            testsPassed++;
            System.out.println("✓ PASS");
        } catch (AssertionError e) {
            testsFailed++;
            System.out.println("✗ FAIL");
            System.out.println("      Error: " + e.getMessage());
        } catch (Exception e) {
            testsFailed++;
            System.out.println("✗ ERROR");
            System.out.println("      Exception: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static void printCategory(String category) {
        System.out.println();
        System.out.println("─".repeat(80));
        System.out.println("  " + category);
        System.out.println("─".repeat(80));
    }

    private static void cleanupVault() {
        try {
            VaultSession.lock();
            if (VaultStorage.exists()) {
                VaultStorage.deleteVault();
            }
        } catch (Exception e) {
            // Ignore cleanup errors
        }
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void assertFalse(boolean condition, String message) {
        if (condition) {
            throw new AssertionError(message);
        }
    }

    private static void assertEquals(Object expected, Object actual, String message) {
        if (expected == null && actual == null) return;
        if (expected == null || !expected.equals(actual)) {
            throw new AssertionError(message + " (expected: " + expected + ", actual: " + actual + ")");
        }
    }

    private static void assertNotNull(Object obj, String message) {
        if (obj == null) {
            throw new AssertionError(message);
        }
    }

    private static void assertNull(Object obj, String message) {
        if (obj != null) {
            throw new AssertionError(message);
        }
    }

    private static void fail(String message) {
        throw new AssertionError(message);
    }

    @FunctionalInterface
    interface TestRunnable {
        void run() throws Exception;
    }

}
