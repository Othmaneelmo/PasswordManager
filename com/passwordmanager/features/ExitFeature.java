package com.passwordmanager.features.system;

import com.passwordmanager.features.AbstractFeature;
import com.passwordmanager.features.FeatureCategory;
import com.passwordmanager.storage.VaultSession;

import java.io.Console;

/**
 * Feature for exiting the application.
 * <p>
 * This feature:
 * - Locks the vault if unlocked
 * - Confirms the exit operation
 * - Sets a flag to terminate the menu loop
 * </p>
 * 
 * <p><b>Implementation Note:</b></p>
 * <p>
 * This feature uses a simple flag mechanism. The menu system checks
 * {@link #shouldExit()} after each feature execution to determine
 * if the application should terminate.
 * </p>
 */
public final class ExitFeature extends AbstractFeature {
    private final VaultSession vaultSession;
    private volatile boolean exitRequested = false;

    /**
     * Constructs the exit feature.
     *
     * @param vaultSession the vault session (dependency injected)
     * @throws IllegalArgumentException if vaultSession is null
     */
    public ExitFeature(VaultSession vaultSession) {
        super(
            "exit",
            "Exit",
            "Locks the vault and exits the application"
        );

        if (vaultSession == null) {
            throw new IllegalArgumentException("VaultSession cannot be null");
        }

        this.vaultSession = vaultSession;
    }

    @Override
    public boolean requiresUnlockedVault() {
        return false;
    }

    @Override
    public FeatureCategory getCategory() {
        return FeatureCategory.SYSTEM;
    }

    @Override
    public int getSortOrder() {
        return 100; // Always last
    }

    @Override
    protected void executeInternal(Console console) {
        console.printf("%n=== Exit ===%n");

        // Lock vault if unlocked
        if (vaultSession.isUnlocked()) {
            console.printf("Locking vault...%n");
            vaultSession.lock();
            console.printf("✓ Vault locked.%n");
        }

        console.printf("Goodbye!%n");
        exitRequested = true;
    }

    /**
     * Returns whether the user has requested to exit.
     * <p>
     * The menu system should check this flag after executing any feature
     * and terminate the loop if {@code true}.
     * </p>
     *
     * @return {@code true} if exit was requested
     */
    public boolean shouldExit() {
        return exitRequested;
    }

    /**
     * Resets the exit flag.
     * <p>
     * Useful for testing or if the application needs to restart the menu.
     * </p>
     */
    public void resetExitFlag() {
        exitRequested = false;
    }
}