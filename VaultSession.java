/*The following class:
 * 
 * VaultSession manages the unlocked state of the vault.
 *
 * - Locked by default.
 * - When unlocked, it holds the derived AES key in memory.
 * - When locked, the key is securely wiped and no operations are possible.
*/

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class VaultSession{
    private static boolean unlocked = false;
    private static SecretKey vaultSessionKey = null;
    
    public static void unlock(byte[] keyBytes){
        if(unlocked){
            throw new IllegalStateException("Vault is already unlocked!");
        }
        //Wrap key material in a SecretKey (AES key)
        vaultSessionKey = new SecretKeySpec(keyBytes, "AES");
        unlocked = true;

    }

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

    public static boolean isUnlocked(){
        return unlocked;
    }

    public static SecretKey getVaultSessionKey(){
        if(!unlocked || vaultSessionKey == null){
            throw new IllegalStateException("Vault is locked, Unlock first");
        }
        return vaultSessionKey;
    }
}


