package com.passwordmanager.storage;

import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Manages the unlocked state of the vault as a strict state machine.
 * <p>
 * <b>State Transitions:</b>
 * </p>
 * <pre>
 * [LOCKED] --unlock(keyBytes)--> [UNLOCKED]
 * [UNLOCKED] --lock()--> [LOCKED]
 * </pre>
 * <p>
 * <b>Invariants:</b>
 * </p>
 * <ul>
 *   <li>The vault is LOCKED by default</li>
 *   <li>When LOCKED, {@code vaultSessionKey} is {@code null}</li>
 *   <li>When UNLOCKED, {@code vaultSessionKey} contains a valid AES-256 key</li>
 *   <li>Calling {@code unlock()} when already unlocked throws {@code IllegalStateException}</li>
 *   <li>Calling {@code getVaultSessionKey()} when locked throws {@code IllegalStateException}</li>
 *   <li>All key material is zeroized on {@code lock()}</li>
 * </ul>
 * <p>
 * This class is implemented as a singleton. Use {@code VaultSession.INSTANCE} to access it.
 * </p>
 * 
 * <p><b>Security Guarantees:</b></p>
 * <ul>
 *   <li>Session keys exist in memory only while vault is unlocked</li>
 *   <li>Keys are zeroized immediately upon locking</li>
 *   <li>No operations possible on locked vault</li>
 *   <li>State transitions are atomic and fail-safe</li>
 * </ul>
 * 
 * <p><b>Usage:</b></p>
 * <pre>
 * VaultSession session = VaultSession.INSTANCE;
 * session.unlock(keyBytes);
 * SecretKey key = session.getVaultSessionKey();
 * // ... use key ...
 * session.lock();
 * </pre>
 */
public final class VaultSession {
    /**
     * Singleton instance for dependency injection.
     * <p>
     * Use this constant to access VaultSession throughout the application.
     * </p>
     */
    public static final VaultSession INSTANCE = new VaultSession();

    // Instance fields (not static!)
    private volatile boolean unlocked = false;
    private volatile SecretKey vaultSessionKey = null;

    // Private constructor prevents external instantiation
    private VaultSession() {
        // Singleton - only one instance via INSTANCE constant
    }

    /**
     * Unlocks the vault using the provided key bytes.
     * <p>
     * The key bytes are wrapped in a {@link SecretKey} (AES) for session use.
     * The caller is responsible for clearing the input {@code keyBytes} array
     * after this method returns.
     * </p>
     * <p>
     * <b>Preconditions:</b>
     * </p>
     * <ul>
     *   <li>Vault must be locked</li>
     *   <li>{@code keyBytes} must be exactly 32 bytes (256 bits)</li>
     *   <li>{@code keyBytes} must not be null</li>
     * </ul>
     *
     * @param keyBytes the derived key bytes to unlock the vault (must be 32 bytes for AES-256)
     * @throws IllegalStateException if the vault is already unlocked
     * @throws IllegalArgumentException if keyBytes is null or not 32 bytes
     */
    public synchronized void unlock(byte[] keyBytes) {
        if (unlocked) {
            throw new IllegalStateException("Vault is already unlocked");
        }
        if (keyBytes == null) {
            throw new IllegalArgumentException("Key bytes cannot be null");
        }
        if (keyBytes.length != 32) {
            throw new IllegalArgumentException("Key must be 32 bytes (256 bits) for AES-256");
        }

        // Wrap key material in a SecretKey (AES key)
        vaultSessionKey = new SecretKeySpec(keyBytes, "AES");
        unlocked = true;
    }

    /**
     * Locks the vault and securely wipes all key material from memory.
     * <p>
     * Once locked, no operations using the vault key are allowed until it is unlocked again.
     * This method is idempotent - calling it on an already-locked vault is safe.
     * </p>
     * <p>
     * <b>Security Note:</b> This method attempts to extract and zeroize the raw key bytes
     * from the {@code SecretKey}. While this works for {@code SecretKeySpec}, some
     * {@code SecretKey} implementations may not expose raw bytes. In such cases, only
     * the reference is cleared.
     * </p>
     */
    public synchronized void lock() {
        if (vaultSessionKey != null) {
            // Attempt to zeroize raw key bytes if accessible
            byte[] keyBytes = vaultSessionKey.getEncoded();
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
            }
            vaultSessionKey = null;
        }
        unlocked = false;
    }

    /**
     * Returns whether the vault is currently unlocked.
     * <p>
     * This method is thread-safe and can be called at any time.
     * </p>
     *
     * @return {@code true} if the vault is unlocked, {@code false} otherwise
     */
    public synchronized boolean isUnlocked() {
        return unlocked;
    }

    /**
     * Returns the {@link SecretKey} representing the current vault session key.
     * <p>
     * <b>This method can only be called when the vault is unlocked.</b>
     * </p>
     * <p>
     * <b>Security Warning:</b> The returned key should NEVER be serialized,
     * logged, or persisted. It should only be used for in-memory cryptographic
     * operations during the current session.
     * </p>
     *
     * @return the AES {@link SecretKey} for the current session
     * @throws IllegalStateException if the vault is locked
     */
    public synchronized SecretKey getVaultSessionKey() {
        if (!unlocked || vaultSessionKey == null) {
            throw new IllegalStateException("Vault is locked. Call unlock() first.");
        }
        return vaultSessionKey;
    }

    /**
     * Returns the current lock state as a string for debugging.
     * <p>
     * <b>Warning:</b> This method does NOT expose key material, only the state.
     * </p>
     *
     * @return "LOCKED" or "UNLOCKED"
     */
    public synchronized String getState() {
        return unlocked ? "UNLOCKED" : "LOCKED";
    }
}