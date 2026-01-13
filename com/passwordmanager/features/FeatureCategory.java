package com.passwordmanager.features;

/**
 * Categorizes features for organized menu display.
 * <p>
 * Categories allow the menu system to:
 * - Group related features together
 * - Display features in logical sections
 * - Apply category-level permissions or settings
 * </p>
 * 
 * <p><b>Menu Organization:</b></p>
 * <pre>
 * === ENCRYPTION ===
 * 1. Encrypt Data
 * 2. Decrypt Data
 * 
 * === PASSWORD MANAGEMENT ===
 * 3. Add Password
 * 4. Retrieve Password
 * 
 * === SYSTEM ===
 * 5. Lock Vault
 * 6. Exit
 * </pre>
 */
public enum FeatureCategory {
    /**
     * Encryption and decryption operations.
     * <p>
     * Examples: Encrypt data, decrypt data, encrypt file, decrypt file
     * </p>
     */
    ENCRYPTION("Encryption"),

    /**
     * File operations (encryption, steganography, archiving).
     * <p>
     * Examples: Encrypt file, hide file in image, secure delete
     * </p>
     */
    FILE_MANAGEMENT("File Management"),

    /**
     * Password storage and retrieval.
     * <p>
     * Examples: Add password, retrieve password, generate password
     * </p>
     */
    PASSWORD_MANAGEMENT("Password Management"),

    /**
     * Configuration and preferences.
     * <p>
     * Examples: Change master password, configure security profile
     * </p>
     */
    SETTINGS("Settings"),

    /**
     * Vault maintenance and system operations.
     * <p>
     * Examples: Lock vault, backup vault, export data, exit
     * </p>
     */
    SYSTEM("System"),

    /**
     * Uncategorized or experimental features.
     * <p>
     * Used as the default category.
     * </p>
     */
    OTHER("Other");

    private final String displayName;

    FeatureCategory(String displayName) {
        this.displayName = displayName;
    }

    /**
     * Returns the human-readable category name.
     *
     * @return the display name
     */
    public String getDisplayName() {
        return displayName;
    }
}