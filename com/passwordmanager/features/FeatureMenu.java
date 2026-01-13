package com.passwordmanager.features;

import com.passwordmanager.features.system.ExitFeature;
import com.passwordmanager.storage.VaultSession;

import java.io.Console;
import java.util.List;
import java.util.Map;

/**
 * Console-based menu system for feature selection and execution.
 * <p>
 * This class:
 * - Displays available features organized by category
 * - Handles user input and feature selection
 * - Validates vault lock state before executing features
 * - Manages the main application loop
 * </p>
 * 
 * <p><b>Design Principles:</b></p>
 * <ul>
 *   <li><b>Separation of Concerns:</b> Menu display vs. feature execution</li>
 *   <li><b>Fail-Safe:</b> Invalid input is handled gracefully</li>
 *   <li><b>User-Friendly:</b> Clear prompts and error messages</li>
 *   <li><b>Extensible:</b> New features automatically appear in the menu</li>
 * </ul>
 * 
 * <p><b>Menu Layout:</b></p>
 * <pre>
 * ================================================================================
 *                         Password Manager - Main Menu
 * ================================================================================
 * Vault Status: UNLOCKED
 * 
 * === ENCRYPTION ===
 * [1] Encrypt Data
 * [2] Decrypt Data
 * 
 * === SYSTEM ===
 * [3] Lock Vault
 * [4] Exit
 * 
 * Select an option (1-4): _
 * </pre>
 */
public final class FeatureMenu {
    private final FeatureRegistry registry;
    private final VaultSession vaultSession;
    private final Console console;

    /**
     * Constructs a feature menu.
     *
     * @param registry the feature registry
     * @param vaultSession the vault session
     * @param console the console for I/O
     * @throws IllegalArgumentException if any parameter is null
     */
    public FeatureMenu(FeatureRegistry registry, VaultSession vaultSession, Console console) {
        if (registry == null) {
            throw new IllegalArgumentException("FeatureRegistry cannot be null");
        }
        if (vaultSession == null) {
            throw new IllegalArgumentException("VaultSession cannot be null");
        }
        if (console == null) {
            throw new IllegalArgumentException("Console cannot be null");
        }

        this.registry = registry;
        this.vaultSession = vaultSession;
        this.console = console;
    }

    /**
     * Runs the main menu loop.
     * <p>
     * This method:
     * 1. Displays the menu
     * 2. Prompts for user input
     * 3. Executes the selected feature
     * 4. Repeats until exit is requested
     * </p>
     * <p>
     * The loop terminates when the {@link ExitFeature} is executed.
     * </p>
     */
    public void run() {
        ExitFeature exitFeature = findExitFeature();

        while (true) {
            displayMenu();

            String input = console.readLine("%nSelect an option: ");

            if (input == null || input.trim().isEmpty()) {
                console.printf("Invalid input. Please enter a number.%n");
                continue;
            }

            int choice;
            try {
                choice = Integer.parseInt(input.trim());
            } catch (NumberFormatException e) {
                console.printf("Invalid input. Please enter a number.%n");
                continue;
            }

            Feature selected = getFeatureByMenuNumber(choice);

            if (selected == null) {
                console.printf("Invalid option. Please try again.%n");
                continue;
            }

            executeFeature(selected);

            // Check if exit was requested
            if (exitFeature != null && exitFeature.shouldExit()) {
                break;
            }
        }
    }

    /**
     * Displays the main menu with all enabled features.
     */
    private void displayMenu() {
        console.printf("%n");
        console.printf("=".repeat(80));
        console.printf("%n");
        console.printf("                    Password Manager - Main Menu%n");
        console.printf("=".repeat(80));
        console.printf("%n");
        console.printf("Vault Status: %s%n", vaultSession.getState());
        console.printf("%n");

        Map<FeatureCategory, List<Feature>> featuresByCategory = registry.getFeaturesByCategory();
        int menuNumber = 1;

        for (Map.Entry<FeatureCategory, List<Feature>> entry : featuresByCategory.entrySet()) {
            FeatureCategory category = entry.getKey();
            List<Feature> features = entry.getValue();

            if (features.isEmpty()) {
                continue;
            }

            console.printf("=== %s ===%n", category.getDisplayName().toUpperCase());

            for (Feature feature : features) {
                console.printf("[%d] %s%n", menuNumber, feature.getDisplayName());

                // Show lock indicator for features requiring unlocked vault
                if (feature.requiresUnlockedVault() && !vaultSession.isUnlocked()) {
                    console.printf("    (requires unlocked vault)%n");
                }

                menuNumber++;
            }

            console.printf("%n");
        }
    }

    /**
     * Executes a feature with proper validation.
     */
    private void executeFeature(Feature feature) {
        // Check if feature requires unlocked vault
        if (feature.requiresUnlockedVault() && !vaultSession.isUnlocked()) {
            console.printf("%n");
            console.printf("Error: This feature requires an unlocked vault.%n");
            console.printf("Please unlock the vault first.%n");
            console.printf("%nPress ENTER to continue...");
            console.readLine();
            return;
        }

        // Execute the feature
        try {
            feature.execute(console);
        } catch (Exception e) {
            console.printf("%nUnexpected error: %s%n", e.getMessage());
            if (Boolean.getBoolean("vault.debug")) {
                e.printStackTrace();
            }
            console.printf("%nPress ENTER to continue...");
            console.readLine();
        }
    }

    /**
     * Retrieves a feature by its menu number.
     *
     * @param menuNumber the menu number (1-based)
     * @return the feature, or null if not found
     */
    private Feature getFeatureByMenuNumber(int menuNumber) {
        if (menuNumber < 1) {
            return null;
        }

        List<Feature> allFeatures = registry.getEnabledFeatures();

        if (menuNumber > allFeatures.size()) {
            return null;
        }

        return allFeatures.get(menuNumber - 1);
    }

    /**
     * Finds the ExitFeature in the registry.
     *
     * @return the ExitFeature, or null if not registered
     */
    private ExitFeature findExitFeature() {
        Feature exitFeature = registry.getFeatureById("exit");
        if (exitFeature instanceof ExitFeature) {
            return (ExitFeature) exitFeature;
        }
        return null;
    }

    /**
     * Displays a help message showing feature descriptions.
     */
    public void showHelp() {
        console.printf("%n=== Feature Descriptions ===%n%n");

        Map<FeatureCategory, List<Feature>> featuresByCategory = registry.getFeaturesByCategory();

        for (Map.Entry<FeatureCategory, List<Feature>> entry : featuresByCategory.entrySet()) {
            FeatureCategory category = entry.getKey();
            List<Feature> features = entry.getValue();

            if (features.isEmpty()) {
                continue;
            }

            console.printf("--- %s ---%n", category.getDisplayName());

            for (Feature feature : features) {
                console.printf("%s:%n", feature.getDisplayName());
                console.printf("  %s%n", feature.getDescription());
                console.printf("%n");
            }
        }
    }
}