package com.passwordmanager.features.system;

import com.passwordmanager.features.AbstractFeature;
import com.passwordmanager.features.FeatureCategory;
import com.passwordmanager.storage.VaultSession;

import java.io.Console;

/**
 * Feature for locking the vault.
 * <p>
 * This feature:
 * - Locks the vault (zeroizes session key)
 * - Confirms the lock operation to the user
 * - Returns control to the menu (which will detect the locked state)
 * </p>
 * 
 * <p><b>Security Notes:</b></p>
 * <ul>
 *   <li>Session key is securely zeroized</li>
 *   <li>All subsequent operations requiring vault access will fail</li>
 *   <li>User must unlock again to access encrypted data</li>
 * </ul>
 */
public final class LockVaultFeature extends AbstractFeature {
    private final VaultSession vaultSession;

    /**
     * Constructs the lock vault feature.
     *
     * @param vaultSession the vault session (dependency injected)
     * @throws IllegalArgumentException if vaultSession is null
     */
    public LockVaultFeature(VaultSession vaultSession) {
        super(
            "lock-vault",
            "Lock Vault",
            "Locks the vault and clears the session key from memory"
        );

        if (vaultSession == null) {
            throw new IllegalArgumentException("VaultSession cannot be null");
        }

        this.vaultSession = vaultSession;
    }

    @Override
    public boolean requiresUnlockedVault() {
        // Can be called even when locked (it's idempotent)
        return false;
    }

    @Override
    public FeatureCategory getCategory() {
        return FeatureCategory.SYSTEM;
    }

    @Override
    public int getSortOrder() {
        return 90; // Near the end, before Exit
    }

    @Override
    protected void executeInternal(Console console) {
        console.printf("%n=== Lock Vault ===%n");

        if (!vaultSession.isUnlocked()) {
            console.printf("Vault is already locked.%n");
        } else {
            vaultSession.lock();
            console.printf("✓ Vault locked successfully.%n");
            console.printf("Session key has been cleared from memory.%n");
            console.printf("%nYou must unlock the vault again to access encrypted data.%n");
        }

        console.printf("%nPress ENTER to continue...");
        console.readLine();
    }
}