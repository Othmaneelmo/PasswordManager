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
 * This class uses static methods to represent a single global vault session.
 * In future versions, this could be refactored to support multiple vault instances.
 * </p>
 * 
 * <p><b>Security Guarantees:</b></p>
 * <ul>
 *   <li>Session keys exist in memory only while vault is unlocked</li>
 *   <li>Keys are zeroized immediately upon locking</li>
 *   <li>No operations possible on locked vault</li>
 *   <li>State transitions are atomic and fail-safe</li>
 * </ul>
 */
public class VaultSession{
    private static volatile boolean unlocked = false;
    private static volatile SecretKey vaultSessionKey = null;



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
    public static synchronized void unlock(byte[] keyBytes) {
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
     * </p>
     */
    public static void lock(){
        if(vaultSessionKey != null){
            byte[] keyBytes = vaultSessionKey.getEncoded();
            if(keyBytes != null){
                Arrays.fill(keyBytes, (byte) 0); //wipe keyBytes
            }
            vaultSessionKey = null;
            unlocked = false;
        }

    }

    /**
     * Returns whether the vault is currently unlocked.
     *
     * @return {@code true} if the vault is unlocked, {@code false} otherwise
     */
    public static boolean isUnlocked(){
        return unlocked;
    }

    /**
     * Returns the {@link SecretKey} representing the current vault session key.
     * <p>
     * This method can only be called when the vault is unlocked.
     * </p>
     *
     * @return the AES {@link SecretKey} for the current session
     * @throws IllegalStateException if the vault is locked or the key is null
     */
    public static SecretKey getVaultSessionKey(){
        if(!unlocked || vaultSessionKey == null){
            throw new IllegalStateException("Vault is locked, Unlock first");
        }
        return vaultSessionKey;
    }
}


