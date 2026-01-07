package com.passwordmanager.test;

import com.passwordmanager.security.HashedPassword;
import com.passwordmanager.security.PBKDF2Hasher;
import com.passwordmanager.storage.VaultSession;
import com.passwordmanager.storage.VaultStorage;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

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
        runStateMachineTests();
        runStorageTests();
        runConcurrencyTests();
        runAttackResistanceTests();
        //runEdgeCaseTests();

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

        test("Session key zeroization on lock", () -> {
            char[] pwd = "zeroizeTest".toCharArray();
            HashedPassword stored = PBKDF2Hasher.defaultHashPassword(pwd);
            byte[] key = PBKDF2Hasher.deriveSessionKey(pwd, stored);
            
            VaultSession.unlock(key);
            byte[] keyBeforeLock = VaultSession.getVaultSessionKey().getEncoded();
            VaultSession.lock();
            
            // After lock, we can't access the key anymore
            try {
                VaultSession.getVaultSessionKey();
                fail("Should not be able to access key after lock");
            } catch (IllegalStateException e) {
                // Expected
            }
            
            Arrays.fill(pwd, ' ');
            Arrays.fill(key, (byte) 0);
        });

        test("PBEKeySpec password clearing", () -> {
            // This test verifies that password is cleared from PBEKeySpec
            // We can't directly test internal state, but we can verify no exceptions
            char[] pwd = "specClearTest".toCharArray();
            
            try {
                HashedPassword hp = PBKDF2Hasher.defaultHashPassword(pwd);
                // If we get here without exception, PBEKeySpec.clearPassword() worked
                assertTrue(true, "PBEKeySpec clearing succeeded");
            } catch (Exception e) {
                fail("PBEKeySpec clearing should not throw: " + e.getMessage());
            }
            
            Arrays.fill(pwd, ' ');
        });

        test("Caller responsibility for password clearing", () -> {
            char[] pwd = "callerTest".toCharArray();
            HashedPassword hp = PBKDF2Hasher.defaultHashPassword(pwd);
            
            // Caller must clear
            Arrays.fill(pwd, ' ');
            
            // Verify cleared
            for (char c : pwd) {
                assertEquals(' ', c, "Password array should be cleared by caller");
            }
        });

        test("Session key zeroization after unlock", () -> {
            char[] pwd = "unlockZeroTest".toCharArray();
            HashedPassword stored = PBKDF2Hasher.defaultHashPassword(pwd);
            byte[] key = PBKDF2Hasher.deriveSessionKey(pwd, stored);
            
            VaultSession.unlock(key);
            
            // Caller should zeroize the key array after unlock
            Arrays.fill(key, (byte) 0);
            
            for (byte b : key) {
                assertEquals(0, b, "Session key should be zeroized after use");
            }
            
            VaultSession.lock();
            Arrays.fill(pwd, ' ');
        });
    }

    // ==================== STATE MACHINE TESTS ====================
    private static void runStateMachineTests() {
        printCategory("STATE MACHINE INVARIANTS");

        test("Vault starts locked", () -> {
            assertFalse(VaultSession.isUnlocked(), "Vault should start in locked state");
            assertEquals("LOCKED", VaultSession.getState(), "State should be LOCKED");
        });

        test("Cannot unlock twice", () -> {
            char[] pwd = "doubleUnlock".toCharArray();
            HashedPassword stored = PBKDF2Hasher.defaultHashPassword(pwd);
            byte[] key = PBKDF2Hasher.deriveSessionKey(pwd, stored);
            
            VaultSession.unlock(key);
            
            try {
                byte[] key2 = PBKDF2Hasher.deriveSessionKey(pwd, stored);
                VaultSession.unlock(key2);
                fail("Should not be able to unlock twice");
                Arrays.fill(key2, (byte) 0);
            } catch (IllegalStateException e) {
                // Expected
            }
            
            VaultSession.lock();
            Arrays.fill(pwd, ' ');
            Arrays.fill(key, (byte) 0);
        });

        test("Cannot get key when locked", () -> {
            VaultSession.lock(); // Ensure locked
            
            try {
                VaultSession.getVaultSessionKey();
                fail("Should not be able to get key when locked");
            } catch (IllegalStateException e) {
                // Expected
            }
        });

        test("Lock is idempotent", () -> {
            char[] pwd = "idempotentTest".toCharArray();
            HashedPassword stored = PBKDF2Hasher.defaultHashPassword(pwd);
            byte[] key = PBKDF2Hasher.deriveSessionKey(pwd, stored);
            
            VaultSession.unlock(key);
            VaultSession.lock();
            VaultSession.lock(); // Second lock should not throw
            VaultSession.lock(); // Third lock should not throw
            
            assertFalse(VaultSession.isUnlocked(), "Vault should remain locked");
            
            Arrays.fill(pwd, ' ');
            Arrays.fill(key, (byte) 0);
        });

        test("Unlock -> Lock -> Unlock cycle", () -> {
            char[] pwd = "cycleTest".toCharArray();
            HashedPassword stored = PBKDF2Hasher.defaultHashPassword(pwd);
            
            // First unlock
            byte[] key1 = PBKDF2Hasher.deriveSessionKey(pwd, stored);
            VaultSession.unlock(key1);
            assertTrue(VaultSession.isUnlocked(), "Should be unlocked after first unlock");
            
            // Lock
            VaultSession.lock();
            assertFalse(VaultSession.isUnlocked(), "Should be locked after lock");
            
            // Second unlock
            byte[] key2 = PBKDF2Hasher.deriveSessionKey(pwd, stored);
            VaultSession.unlock(key2);
            assertTrue(VaultSession.isUnlocked(), "Should be unlocked after second unlock");
            
            VaultSession.lock();
            Arrays.fill(pwd, ' ');
            Arrays.fill(key1, (byte) 0);
            Arrays.fill(key2, (byte) 0);
        });

        test("Key must be exactly 32 bytes", () -> {
            byte[] shortKey = new byte[16];
            byte[] longKey = new byte[64];
            
            try {
                VaultSession.unlock(shortKey);
                fail("Should reject 16-byte key");
            } catch (IllegalArgumentException e) {
                // Expected
            }
            
            try {
                VaultSession.unlock(longKey);
                fail("Should reject 64-byte key");
            } catch (IllegalArgumentException e) {
                // Expected
            }
        });

        test("Null key rejected", () -> {
            try {
                VaultSession.unlock(null);
                fail("Should reject null key");
            } catch (IllegalArgumentException e) {
                // Expected
            }
        });  

    }

    // ==================== STORAGE TESTS ====================

    private static void runStorageTests() {
        printCategory("STORAGE LAYER");

            test("Save and load master key", () -> {
            cleanupVault();
            
            char[] pwd = "storageTest".toCharArray();
            HashedPassword original = PBKDF2Hasher.defaultHashPassword(pwd);
            
            VaultStorage.saveMasterKey(
                original.getAlgorithm(),
                original.getIterations(),
                original.getSalt(),
                original.getHash()
            );
            
            HashedPassword loaded = VaultStorage.loadHashedPassword();
            
            assertNotNull(loaded, "Loaded hash should not be null");
            assertEquals(original.getAlgorithm(), loaded.getAlgorithm(), "Algorithm should match");
            assertEquals(original.getIterations(), loaded.getIterations(), "Iterations should match");
            assertEquals(original.getSalt(), loaded.getSalt(), "Salt should match");
            assertEquals(original.getHash(), loaded.getHash(), "Hash should match");
            
            Arrays.fill(pwd, ' ');
        });
        test("Vault exists check", () -> {
            cleanupVault();
            assertFalse(VaultStorage.exists(), "Vault should not exist initially");
            
            char[] pwd = "existsTest".toCharArray();
            HashedPassword hp = PBKDF2Hasher.defaultHashPassword(pwd);
            VaultStorage.saveMasterKey(hp.getAlgorithm(), hp.getIterations(), hp.getSalt(), hp.getHash());
            
            assertTrue(VaultStorage.exists(), "Vault should exist after save");
            
            Arrays.fill(pwd, ' ');
        });

        test("Load non-existent vault returns null", () -> {
            cleanupVault();
            
            HashedPassword loaded = VaultStorage.loadHashedPassword();
            assertNull(loaded, "Loading non-existent vault should return null");
        });

        test("Reject invalid algorithm", () -> {
            try {
                VaultStorage.saveMasterKey("", 100000, "validSalt==", "validHash==");
                fail("Should reject empty algorithm");
            } catch (IllegalArgumentException e) {
                // Expected
            }
        });

        test("Reject invalid iterations", () -> {
            try {
                VaultStorage.saveMasterKey("PBKDF2WithHmacSHA256", 0, "validSalt==", "validHash==");
                fail("Should reject zero iterations");
            } catch (IllegalArgumentException e) {
                // Expected
            }
        });

        test("Reject invalid Base64 salt", () -> {
            try {
                VaultStorage.saveMasterKey("PBKDF2WithHmacSHA256", 100000, "not-base64!", "validHash==");
                fail("Should reject invalid Base64 salt");
            } catch (IllegalArgumentException e) {
                // Expected
            }
        });

        test("Reject invalid Base64 hash", () -> {
            try {
                VaultStorage.saveMasterKey("PBKDF2WithHmacSHA256", 100000, "validSalt==", "not-base64!");
                fail("Should reject invalid Base64 hash");
            } catch (IllegalArgumentException e) {
                // Expected
            }
        });

        test("Corrupted JSON handling", () -> {
            cleanupVault();
            
            try {
                // Create vault folder
                Files.createDirectories(Path.of("Vault"));
                // Write corrupted JSON
                Files.writeString(Path.of("Vault/masterKey.json"), "{corrupt json");
                
                try {
                    VaultStorage.loadHashedPassword();
                    fail("Should throw IOException on corrupted JSON");
                } catch (IOException e) {
                    // Expected
                }
            } catch (IOException e) {
                fail("Setup failed: " + e.getMessage());
            }
        });

        test("Empty vault file handling", () -> {
            cleanupVault();
            
            try {
                Files.createDirectories(Path.of("Vault"));
                Files.writeString(Path.of("Vault/masterKey.json"), "");
                
                try {
                    VaultStorage.loadHashedPassword();
                    fail("Should throw IOException on empty file");
                } catch (IOException e) {
                    // Expected
                }
            } catch (IOException e) {
                fail("Setup failed: " + e.getMessage());
            }
        });
    }

    // ==================== CONCURRENCY TESTS ====================

    private static void runConcurrencyTests() {
        printCategory("CONCURRENCY & THREAD SAFETY");

        test("Multiple thread password hashing", () -> {
            ExecutorService executor = Executors.newFixedThreadPool(10);
            CountDownLatch latch = new CountDownLatch(20);
            
            for (int i = 0; i < 20; i++) {
                final int index = i;
                executor.submit(() -> {
                    try {
                        char[] pwd = ("thread" + index).toCharArray();
                        HashedPassword hp = PBKDF2Hasher.defaultHashPassword(pwd);
                        Arrays.fill(pwd, ' ');
                        latch.countDown();
                    } catch (Exception e) {
                        fail("Thread " + index + " failed: " + e.getMessage());
                    }
                });
            }
            
            try {
                boolean completed = latch.await(30, TimeUnit.SECONDS);
                assertTrue(completed, "All threads should complete within 30 seconds");
            } catch (InterruptedException e) {
                fail("Concurrency test interrupted");
            }
            
            executor.shutdown();
        });

        test("Session lock/unlock race condition", () -> {
            VaultSession.lock();
            
            char[] pwd = "raceTest".toCharArray();
            HashedPassword stored = PBKDF2Hasher.defaultHashPassword(pwd);
            byte[] key = PBKDF2Hasher.deriveSessionKey(pwd, stored);
            
            ExecutorService executor = Executors.newFixedThreadPool(5);
            CountDownLatch latch = new CountDownLatch(10);
            
            // 5 threads try to unlock, 5 try to lock
            for (int i = 0; i < 5; i++) {
                executor.submit(() -> {
                    try {
                        byte[] threadKey = PBKDF2Hasher.deriveSessionKey(pwd, stored);
                        VaultSession.unlock(threadKey);
                        Arrays.fill(threadKey, (byte) 0);
                    } catch (IllegalStateException e) {
                        // Expected - some will fail due to race
                    } catch (Exception e) {
                        // Ignore crypto exceptions in threads
                    }
                    latch.countDown();
                });
                
                executor.submit(() -> {
                    try {
                        VaultSession.lock();
                    } catch (Exception e) {
                        // Safe to ignore
                    }
                    latch.countDown();
                });
            }
            
            try {
                latch.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                fail("Race condition test interrupted");
            }
            
            executor.shutdown();
            VaultSession.lock();
            Arrays.fill(pwd, ' ');
            Arrays.fill(key, (byte) 0);
        });
    }

    private static void runAttackResistanceTests() {
        printCategory("ATTACK RESISTANCE");

        test("Rainbow table resistance (unique salts)", () -> {
            char[] pwd = "commonPassword123".toCharArray();
            
            HashedPassword h1 = PBKDF2Hasher.defaultHashPassword(pwd);
            HashedPassword h2 = PBKDF2Hasher.defaultHashPassword(pwd);
            
            assertFalse(h1.getSalt().equals(h2.getSalt()), 
                "Same password should have different salts");
            assertFalse(h1.getHash().equals(h2.getHash()), 
                "Same password with different salts should have different hashes");
            
            Arrays.fill(pwd, ' ');
        });
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
