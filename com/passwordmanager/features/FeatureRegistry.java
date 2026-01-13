package com.passwordmanager.features;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Central registry for all available features.
 * <p>
 * The registry:
 * - Stores all registered features
 * - Provides feature lookup by ID
 * - Filters enabled/disabled features
 * - Organizes features by category and sort order
 * - Supports dynamic feature registration (plugin-like)
 * </p>
 * 
 * <p><b>Design Principles:</b></p>
 * <ul>
 *   <li><b>Single Source of Truth:</b> All features registered here</li>
 *   <li><b>Fail-Fast:</b> Duplicate IDs rejected immediately</li>
 *   <li><b>Thread-Safe:</b> Safe for concurrent registration (rare in practice)</li>
 *   <li><b>Immutable Views:</b> Returns defensive copies to prevent external modification</li>
 * </ul>
 * 
 * <p><b>Usage Example:</b></p>
 * <pre>
 * FeatureRegistry registry = new FeatureRegistry();
 * 
 * // Register features during startup
 * registry.register(new EncryptDataFeature(vaultSession));
 * registry.register(new DecryptDataFeature(vaultSession));
 * registry.register(new LockVaultFeature(vaultSession));
 * 
 * // Get features for menu display
 * List&lt;Feature&gt; menuFeatures = registry.getEnabledFeatures();
 * 
 * // Execute a specific feature
 * Feature selected = registry.getFeatureById("encrypt-data");
 * if (selected != null) {
 *     selected.execute(console);
 * }
 * </pre>
 * 
 * <p><b>Future Extensions:</b></p>
 * <ul>
 *   <li>Feature plugins loaded from JAR files</li>
 *   <li>Feature dependencies and ordering constraints</li>
 *   <li>Feature permissions and role-based access control</li>
 *   <li>Feature lifecycle management (enable/disable at runtime)</li>
 * </ul>
 */
public final class FeatureRegistry {
    private final Map<String, Feature> features;
    private final Object lock = new Object();

    /**
     * Creates an empty feature registry.
     */
    public FeatureRegistry() {
        this.features = new LinkedHashMap<>();
    }

    /**
     * Registers a feature with this registry.
     * <p>
     * <b>Thread-Safe:</b> Multiple threads can register features concurrently.
     * </p>
     * <p>
     * <b>Duplicate Prevention:</b> If a feature with the same ID already exists,
     * this method throws {@link IllegalArgumentException}.
     * </p>
     *
     * @param feature the feature to register (must not be null)
     * @throws IllegalArgumentException if feature is null or ID already registered
     */
    public void register(Feature feature) {
        if (feature == null) {
            throw new IllegalArgumentException("Feature cannot be null");
        }

        String id = feature.getId();
        if (id == null || id.trim().isEmpty()) {
            throw new IllegalArgumentException("Feature ID cannot be null or empty");
        }

        synchronized (lock) {
            if (features.containsKey(id)) {
                throw new IllegalArgumentException(
                    "Feature with ID '" + id + "' is already registered"
                );
            }
            features.put(id, feature);
        }
    }

    /**
     * Unregisters a feature from this registry.
     * <p>
     * If no feature with the given ID exists, this method does nothing.
     * </p>
     *
     * @param featureId the ID of the feature to unregister
     */
    public void unregister(String featureId) {
        if (featureId == null) {
            return;
        }

        synchronized (lock) {
            features.remove(featureId);
        }
    }

    /**
     * Retrieves a feature by its ID.
     *
     * @param featureId the feature ID to look up
     * @return the feature, or {@code null} if not found
     */
    public Feature getFeatureById(String featureId) {
        if (featureId == null) {
            return null;
        }

        synchronized (lock) {
            return features.get(featureId);
        }
    }

    /**
     * Returns all registered features, regardless of enabled state.
     * <p>
     * The returned list is a defensive copy and can be modified safely.
     * </p>
     *
     * @return an immutable list of all features
     */
    public List<Feature> getAllFeatures() {
        synchronized (lock) {
            return new ArrayList<>(features.values());
        }
    }

    /**
     * Returns all enabled features, sorted by category and sort order.
     * <p>
     * Features are sorted:
     * 1. By category (enum ordinal)
     * 2. By sort order within category (ascending)
     * 3. By display name (alphabetically) as tiebreaker
     * </p>
     * <p>
     * The returned list is a defensive copy.
     * </p>
     *
     * @return an immutable list of enabled features
     */
    public List<Feature> getEnabledFeatures() {
        synchronized (lock) {
            return features.values().stream()
                .filter(Feature::isEnabled)
                .sorted(Comparator
                    .comparing((Feature f) -> f.getCategory().ordinal())
                    .thenComparing(Feature::getSortOrder)
                    .thenComparing(Feature::getDisplayName))
                .collect(Collectors.toList());
        }
    }

    /**
     * Returns all enabled features in a specific category.
     *
     * @param category the category to filter by
     * @return an immutable list of enabled features in the category
     */
    public List<Feature> getEnabledFeaturesInCategory(FeatureCategory category) {
        if (category == null) {
            return Collections.emptyList();
        }

        synchronized (lock) {
            return features.values().stream()
                .filter(Feature::isEnabled)
                .filter(f -> f.getCategory() == category)
                .sorted(Comparator
                    .comparing(Feature::getSortOrder)
                    .thenComparing(Feature::getDisplayName))
                .collect(Collectors.toList());
        }
    }

    /**
     * Returns features grouped by category.
     * <p>
     * The returned map:
     * - Keys: {@link FeatureCategory} values
     * - Values: Lists of enabled features in that category (sorted)
     * - Only includes categories that have at least one enabled feature
     * </p>
     *
     * @return a map of categories to features
     */
    public Map<FeatureCategory, List<Feature>> getFeaturesByCategory() {
        synchronized (lock) {
            return features.values().stream()
                .filter(Feature::isEnabled)
                .collect(Collectors.groupingBy(
                    Feature::getCategory,
                    LinkedHashMap::new,
                    Collectors.collectingAndThen(
                        Collectors.toList(),
                        list -> list.stream()
                            .sorted(Comparator
                                .comparing(Feature::getSortOrder)
                                .thenComparing(Feature::getDisplayName))
                            .collect(Collectors.toList())
                    )
                ));
        }
    }

    /**
     * Returns the total number of registered features.
     *
     * @return the feature count
     */
    public int getFeatureCount() {
        synchronized (lock) {
            return features.size();
        }
    }

    /**
     * Returns the number of enabled features.
     *
     * @return the enabled feature count
     */
    public int getEnabledFeatureCount() {
        synchronized (lock) {
            return (int) features.values().stream()
                .filter(Feature::isEnabled)
                .count();
        }
    }

    /**
     * Checks if a feature with the given ID is registered.
     *
     * @param featureId the feature ID to check
     * @return {@code true} if registered, {@code false} otherwise
     */
    public boolean hasFeature(String featureId) {
        if (featureId == null) {
            return false;
        }

        synchronized (lock) {
            return features.containsKey(featureId);
        }
    }

    /**
     * Clears all registered features.
     * <p>
     * <b>Warning:</b> This is a destructive operation. Use with caution.
     * Primarily intended for testing.
     * </p>
     */
    public void clear() {
        synchronized (lock) {
            features.clear();
        }
    }
}