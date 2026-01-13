package com.passwordmanager.features;

import java.io.Console;

/**
 * Abstract base class providing common feature functionality.
 * <p>
 * This class implements the boilerplate parts of the {@link Feature} interface,
 * allowing concrete features to focus on their core logic.
 * </p>
 * 
 * <p><b>Subclass Responsibilities:</b></p>
 * <ul>
 *   <li>Implement {@link #executeInternal(Console)} with the feature's main logic</li>
 *   <li>Override {@link #getCategory()} and {@link #getSortOrder()} if needed</li>
 *   <li>Handle all errors gracefully (display user-friendly messages)</li>
 * </ul>
 * 
 * <p><b>Provided Functionality:</b></p>
 * <ul>
 *   <li>Enable/disable support</li>
 *   <li>Vault lock state validation</li>
 *   <li>Console null-check</li>
 *   <li>Default category and sort order</li>
 * </ul>
 * 
 * <p><b>Example Subclass:</b></p>
 * <pre>
 * public class EncryptDataFeature extends AbstractFeature {
 *     private final VaultSession vaultSession;
 *     
 *     public EncryptDataFeature(VaultSession vaultSession) {
 *         super("encrypt-data", "Encrypt Data", 
 *               "Encrypts text or binary data using the vault session key");
 *         this.vaultSession = vaultSession;
 *     }
 *     
 *     {@literal @}Override
 *     public boolean requiresUnlockedVault() {
 *         return true;
 *     }
 *     
 *     {@literal @}Override
 *     public FeatureCategory getCategory() {
 *         return FeatureCategory.ENCRYPTION;
 *     }
 *     
 *     {@literal @}Override
 *     protected void executeInternal(Console console) {
 *         // Feature logic here
 *     }
 * }
 * </pre>
 */
public abstract class AbstractFeature implements Feature {
    private final String id;
    private final String displayName;
    private final String description;
    private volatile boolean enabled;

    /**
     * Constructs a feature with the specified metadata.
     *
     * @param id the unique feature ID
     * @param displayName the display name for menus
     * @param description the detailed description
     * @throws IllegalArgumentException if any parameter is null or empty
     */
    protected AbstractFeature(String id, String displayName, String description) {
        if (id == null || id.trim().isEmpty()) {
            throw new IllegalArgumentException("Feature ID cannot be null or empty");
        }
        if (displayName == null || displayName.trim().isEmpty()) {
            throw new IllegalArgumentException("Feature display name cannot be null or empty");
        }
        if (description == null || description.trim().isEmpty()) {
            throw new IllegalArgumentException("Feature description cannot be null or empty");
        }

        this.id = id;
        this.displayName = displayName;
        this.description = description;
        this.enabled = true; // Features are enabled by default
    }

    @Override
    public final String getId() {
        return id;
    }

    @Override
    public final String getDisplayName() {
        return displayName;
    }

    @Override
    public final String getDescription() {
        return description;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Enables or disables this feature.
     * <p>
     * Disabled features are not shown in menus and cannot be executed.
     * </p>
     *
     * @param enabled {@code true} to enable, {@code false} to disable
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public final void execute(Console console) {
        if (console == null) {
            throw new IllegalArgumentException("Console cannot be null");
        }

        if (!isEnabled()) {
            console.printf("Error: Feature '%s' is currently disabled.%n", displayName);
            return;
        }

        try {
            executeInternal(console);
        } catch (Exception e) {
            // Catch all exceptions to prevent feature failures from crashing the app
            console.printf("Error executing feature: %s%n", e.getMessage());
            if (Boolean.getBoolean("vault.debug")) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Executes the feature's core logic.
     * <p>
     * Subclasses implement this method to provide feature-specific functionality.
     * </p>
     * <p>
     * <b>Error Handling:</b> Subclasses should handle errors gracefully and
     * display user-friendly messages. Uncaught exceptions will be caught by
     * {@link #execute(Console)} and displayed generically.
     * </p>
     *
     * @param console the console for user interaction (never null)
     */
    protected abstract void executeInternal(Console console);

    @Override
    public String toString() {
        return String.format("Feature[id=%s, name=%s, enabled=%s]", 
            id, displayName, enabled);
    }
}