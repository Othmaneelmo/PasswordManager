package com.passwordmanager.features;

import java.io.Console;

/**
 * Represents a single executable feature in the password manager.
 * <p>
 * Each feature encapsulates a complete user workflow (e.g., encrypt data,
 * decrypt data, manage passwords). Features are self-contained, testable,
 * and can be registered dynamically with the {@link FeatureRegistry}.
 * </p>
 * 
 * <p><b>Design Principles:</b></p>
 * <ul>
 *   <li><b>Single Responsibility:</b> Each feature does one thing well</li>
 *   <li><b>Dependency Injection:</b> All dependencies passed via constructor</li>
 *   <li><b>No Static Access:</b> Features never access global state directly</li>
 *   <li><b>Fail-Safe:</b> Features handle their own errors gracefully</li>
 * </ul>
 * 
 * <p><b>Lifecycle:</b></p>
 * <pre>
 * Feature feature = new MyFeature(dependencies...);
 * registry.register(feature);
 * 
 * // Later, when user selects this feature:
 * if (feature.requiresUnlockedVault() && !vaultSession.isUnlocked()) {
 *     // Handle error
 * } else {
 *     feature.execute(console);
 * }
 * </pre>
 * 
 * <p><b>Thread Safety:</b></p>
 * <p>
 * Features are not required to be thread-safe. The menu system executes
 * features sequentially on the main thread.
 * </p>
 * 
 * <p><b>Future Extensions:</b></p>
 * <p>
 * This interface can be extended to support:
 * - Feature permissions and role-based access
 * - Feature dependencies (Feature A requires Feature B)
 * - Feature lifecycle hooks (onEnable, onDisable)
 * - Feature configuration and settings
 * </p>
 */
public interface Feature {
    /**
     * Returns the unique identifier for this feature.
     * <p>
     * The ID is used for feature registration, lookup, and persistence.
     * It should be:
     * - Lowercase
     * - Alphanumeric with hyphens/underscores only
     * - Unique across all features
     * </p>
     * <p>
     * Examples: "encrypt-data", "decrypt-file", "manage-passwords"
     * </p>
     *
     * @return a unique feature identifier
     */
    String getId();

    /**
     * Returns the display name shown in the menu.
     * <p>
     * This should be short, user-friendly, and descriptive.
     * </p>
     * <p>
     * Examples: "Encrypt Data", "Decrypt File", "Manage Passwords"
     * </p>
     *
     * @return the feature's display name
     */
    String getDisplayName();

    /**
     * Returns a detailed description of what this feature does.
     * <p>
     * This is shown in help menus or when the user requests more information.
     * It should explain:
     * - What the feature does
     * - What input it requires
     * - What output it produces
     * </p>
     *
     * @return a detailed feature description
     */
    String getDescription();

    /**
     * Indicates whether this feature requires an unlocked vault.
     * <p>
     * If {@code true}, the menu system will:
     * - Prevent execution if the vault is locked
     * - Show a clear error message to the user
     * - Suggest unlocking the vault first
     * </p>
     * <p>
     * Features that only display information or manage settings
     * typically return {@code false}.
     * </p>
     *
     * @return {@code true} if the vault must be unlocked to execute this feature
     */
    boolean requiresUnlockedVault();

    /**
     * Indicates whether this feature is currently enabled.
     * <p>
     * Disabled features:
     * - Are not shown in the menu
     * - Cannot be executed
     * - Can be re-enabled at runtime
     * </p>
     * <p>
     * This allows features to be conditionally available based on:
     * - System capabilities (e.g., file encryption unavailable on this OS)
     * - User permissions (e.g., admin-only features)
     * - Configuration (e.g., experimental features disabled by default)
     * </p>
     *
     * @return {@code true} if the feature is enabled and available
     */
    boolean isEnabled();

    /**
     * Executes the feature's main functionality.
     * <p>
     * This method:
     * - Interacts with the user via the provided {@link Console}
     * - Performs the feature's core logic
     * - Handles all errors gracefully (never throws unchecked exceptions)
     * - Cleans up sensitive data before returning
     * </p>
     * <p>
     * <b>Preconditions:</b>
     * - If {@link #requiresUnlockedVault()} returns {@code true}, the vault
     *   MUST be unlocked before calling this method (enforced by menu system)
     * - The console MUST NOT be null
     * </p>
     * <p>
     * <b>Error Handling:</b>
     * Features should catch all exceptions internally and display
     * user-friendly error messages. The menu system will continue
     * normally after execution, even if the feature fails.
     * </p>
     *
     * @param console the console for user interaction (never null)
     * @throws IllegalStateException if preconditions are violated
     */
    void execute(Console console);

    /**
     * Returns the feature category for organization in menus.
     * <p>
     * Categories allow features to be grouped logically:
     * - ENCRYPTION: Encrypt/decrypt operations
     * - FILE_MANAGEMENT: File operations
     * - PASSWORD_MANAGEMENT: Password storage/retrieval
     * - SETTINGS: Configuration and preferences
     * - SYSTEM: Vault maintenance, backup, etc.
     * </p>
     * <p>
     * Default implementation returns {@link FeatureCategory#OTHER}.
     * </p>
     *
     * @return the feature's category
     */
    default FeatureCategory getCategory() {
        return FeatureCategory.OTHER;
    }

    /**
     * Returns the sort order for this feature within its category.
     * <p>
     * Lower numbers appear first. Default is 100.
     * </p>
     * <p>
     * This allows fine-grained control over menu ordering:
     * - Critical features: 0-49
     * - Common features: 50-99
     * - Advanced features: 100-149
     * - Experimental features: 150+
     * </p>
     *
     * @return the sort order (default 100)
     */
    default int getSortOrder() {
        return 100;
    }
}