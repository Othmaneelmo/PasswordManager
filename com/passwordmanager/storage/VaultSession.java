package com.passwordmanager.storage;
/*The following class:
 * 
 * VaultSession manages the unlocked state of the vault.
 *
 * - Locked by default.
 * - When unlocked, it holds the derived AES key in memory.
 * - When locked, the key is securely wiped and no operations are possible.
*/

import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Manages the unlocked state of the vault.
 * <p>
 * The vault is locked by default. When unlocked, it holds the derived AES key in memory.
 * When locked, the key is securely wiped and no operations are allowed.
 * </p>
 * <p>
 * This class uses static methods and variables to represent a single global vault session.
 * All key material is cleared from memory whenever the vault is locked.
 * </p>
 */
public class VaultSession{
    private static boolean unlocked = false;
    private static SecretKey vaultSessionKey = null;
    
    /**
     * Unlocks the vault using the provided key bytes.
     * <p>
     * Wraps the raw key bytes in a {@link SecretKey} (AES) for session use.
     * The vault cannot be unlocked if it is already unlocked.
     * </p>
     *
     * @param keyBytes the derived key bytes to unlock the vault
     * @throws IllegalStateException if the vault is already unlocked
     */
    public static void unlock(byte[] keyBytes){
        if(unlocked){
            throw new IllegalStateException("Vault is already unlocked!");
        }
        //Wrap key material in a SecretKey (AES key)
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


