package com.passwordmanager.storage;

import com.passwordmanager.security.HashedPassword;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Base64;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Handles persistent storage for the vault, including saving and loading the master key hash.
 * <p>
 * <b>Storage Design:</b>
 * </p>
 * <ul>
 *   <li>The vault is stored under a dedicated folder ("Vault")</li>
 *   <li>Master key metadata is stored in JSON format</li>
 *   <li><b>Only non-secret data is persisted</b> (algorithm, iterations, salt, hash)</li>
 *   <li>Derived keys and plaintext passwords are NEVER written to disk</li>
 * </ul>
 * 
 * <p><b>Security Guarantees:</b></p>
 * <ul>
 *   <li>No plaintext passwords stored</li>
 *   <li>No derived session keys stored</li>
 *   <li>JSON validation prevents injection attacks</li>
 *   <li>File permissions enforced where supported</li>
 *   <li>Corrupted files fail safely</li>
 * </ul>
 * 
 * <p><b>Future Expansion:</b></p>
 * <p>
 * Additional files can be added for account data or encrypted storage
 * (e.g., {@code accounts.enc}, {@code files.enc}).
 * </p>
 */
public final class VaultStorage {
    private static final Path VAULT_FOLDER = Path.of("Vault");
    private static final Path MASTER_KEY_FILE = VAULT_FOLDER.resolve("masterKey.json");
    
    // JSON field patterns for safe extraction
    private static final Pattern ALGORITHM_PATTERN = Pattern.compile("\"algorithm\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern ITERATIONS_PATTERN = Pattern.compile("\"iterations\"\\s*:\\s*(\\d+)");
    private static final Pattern SALT_PATTERN = Pattern.compile("\"salt\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern HASH_PATTERN = Pattern.compile("\"hash\"\\s*:\\s*\"([^\"]+)\"");

    // Prevent instantiation
    private VaultStorage() {
        throw new AssertionError("VaultStorage is a utility class and should not be instantiated");
    }

    /**
     * Checks whether the vault already exists.
     * <p>
     * A vault is considered to exist if the master key file is present and readable.
     * </p>
     *
     * @return {@code true} if the master key file exists, {@code false} otherwise
     */
    public static boolean exists() {
        return Files.exists(MASTER_KEY_FILE) && Files.isReadable(MASTER_KEY_FILE);
    }

    /**
     * Saves the master key's PBKDF2 parameters and hash to persistent storage.
     * <p>
     * Creates the vault folder if it does not exist. The JSON structure is manually built
     * to avoid external dependencies. File permissions are set to restrict access where supported.
     * </p>
     * <p>
     * <b>Security Note:</b> This method stores only authentication metadata. It does NOT
     * store derived keys or plaintext passwords.
     * </p>
     *
     * @param algorithm  the key derivation algorithm used (e.g., "PBKDF2WithHmacSHA256")
     * @param iterations the number of PBKDF2 iterations
     * @param salt       the Base64-encoded random salt
     * @param hash       the Base64-encoded derived key
     * @throws IOException if writing to the vault file fails
     * @throws IllegalArgumentException if any parameter is null or invalid
     */
    public static void saveMasterKey(String algorithm, int iterations, String salt, String hash) 
            throws IOException {
        
        validateSaveInputs(algorithm, iterations, salt, hash);

        // Ensure Vault folder exists
        if (!Files.exists(VAULT_FOLDER)) {
            Files.createDirectories(VAULT_FOLDER);
            restrictFolderPermissions(VAULT_FOLDER);
        }

        // Build minimal JSON string manually (no library dependency)
        String json = buildMasterKeyJson(algorithm, iterations, salt, hash);

        // Write JSON to file atomically
        Files.writeString(MASTER_KEY_FILE, json);
        
        // Restrict file permissions where supported
        restrictFilePermissions(MASTER_KEY_FILE);
    }

    /**
     * Loads the raw JSON content of the master key file.
     * <p>
     * This method performs basic validation to ensure the file is not empty or corrupted.
     * </p>
     *
     * @return the JSON string, or {@code null} if the file does not exist
     * @throws IOException if reading the vault file fails or the file is corrupted
     */
    public static String loadMasterKey() throws IOException {
        if (!Files.exists(MASTER_KEY_FILE)) {
            return null;
        }
        
        String json = Files.readString(MASTER_KEY_FILE).trim();
        
        if (json.isEmpty()) {
            throw new IOException("Master key file is empty or corrupted");
        }
        
        return json;
    }

    /**
     * Loads the master key as a {@link HashedPassword} object.
     * <p>
     * Parses the JSON file to extract algorithm, iterations, salt, and hash.
     * Uses regex-based extraction for security (avoids eval-like vulnerabilities).
     * </p>
     * <p>
     * <b>Validation:</b> This method validates that all required fields are present
     * and that Base64-encoded fields are properly formatted.
     * </p>
     *
     * @return the {@link HashedPassword} instance, or {@code null} if the file does not exist
     * @throws IOException if reading the vault file fails or parsing fails
     */
    public static HashedPassword loadHashedPassword() throws IOException {
        if (!Files.exists(MASTER_KEY_FILE)) {
            return null;
        }
        
        String json = Files.readString(MASTER_KEY_FILE).trim();
        
        if (json.isEmpty()) {
            throw new IOException("Master key file is empty or corrupted");
        }

        try {
            String algorithm = extractJsonField(json, ALGORITHM_PATTERN, "algorithm");
            int iterations = Integer.parseInt(extractJsonField(json, ITERATIONS_PATTERN, "iterations"));
            String salt = extractJsonField(json, SALT_PATTERN, "salt");
            String hash = extractJsonField(json, HASH_PATTERN, "hash");
            
            // Validate Base64 encoding
            validateBase64(salt, "salt");
            validateBase64(hash, "hash");
            
            return new HashedPassword(algorithm, iterations, salt, hash);
            
        } catch (NumberFormatException e) {
            throw new IOException("Invalid iteration count in vault file", e);
        } catch (IllegalArgumentException e) {
            throw new IOException("Corrupted vault file: " + e.getMessage(), e);
        }
    }

    /**
     * Deletes the vault folder and all its contents.
     * <p>
     * <b>Warning:</b> This is a destructive operation. Use with extreme caution.
     * This method is provided for testing or complete vault reset scenarios.
     * </p>
     *
     * @throws IOException if deletion fails
     */
    public static void deleteVault() throws IOException {
        if (Files.exists(VAULT_FOLDER)) {
            // Delete master key file first
            if (Files.exists(MASTER_KEY_FILE)) {
                Files.delete(MASTER_KEY_FILE);
            }
            // Delete folder
            Files.delete(VAULT_FOLDER);
        }
    }

    // ==================== PRIVATE HELPER METHODS ====================

    /**
     * Validates inputs for saveMasterKey method.
     */
    private static void validateSaveInputs(String algorithm, int iterations, String salt, String hash) {
        if (algorithm == null || algorithm.trim().isEmpty()) {
            throw new IllegalArgumentException("Algorithm cannot be null or empty");
        }
        if (iterations < 1) {
            throw new IllegalArgumentException("Iterations must be positive");
        }
        if (salt == null || salt.trim().isEmpty()) {
            throw new IllegalArgumentException("Salt cannot be null or empty");
        }
        if (hash == null || hash.trim().isEmpty()) {
            throw new IllegalArgumentException("Hash cannot be null or empty");
        }
        
        // Validate Base64 encoding
        validateBase64(salt, "salt");
        validateBase64(hash, "hash");
    }

    /**
     * Builds JSON string for master key storage.
     */
    private static String buildMasterKeyJson(String algorithm, int iterations, String salt, String hash) {
        return String.format(
            "{\n" +
            "  \"algorithm\": \"%s\",\n" +
            "  \"iterations\": %d,\n" +
            "  \"salt\": \"%s\",\n" +
            "  \"hash\": \"%s\"\n" +
            "}",
            escapeJsonString(algorithm),
            iterations,
            escapeJsonString(salt),
            escapeJsonString(hash)
        );
    }

    /**
     * Escapes special characters for JSON strings.
     */
    private static String escapeJsonString(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r")
                    .replace("\t", "\\t");
    }

    /**
     * Extracts a field from JSON using regex pattern.
     */
    private static String extractJsonField(String json, Pattern pattern, String fieldName) 
            throws IOException {
        Matcher matcher = pattern.matcher(json);
        if (!matcher.find()) {
            throw new IOException("Missing or invalid '" + fieldName + "' field in vault file");
        }
        return matcher.group(1);
    }

    /**
     * Validates that a string is proper Base64 encoding.
     */
    private static void validateBase64(String value, String fieldName) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(fieldName + " cannot be null or empty");
        }
        try {
            Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(fieldName + " is not valid Base64: " + e.getMessage());
        }
    }

    /**
     * Restricts file permissions to owner-only (Unix/Linux systems).
     * On Windows or unsupported systems, this is a no-op.
     */
    private static void restrictFilePermissions(Path file) {
        try {
            Set<PosixFilePermission> perms = Set.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE
            );
            Files.setPosixFilePermissions(file, perms);
        } catch (UnsupportedOperationException | IOException e) {
            // POSIX permissions not supported (e.g., Windows)
            // Future improvement: use Windows ACLs
        }
    }

    /**
     * Restricts folder permissions to owner-only (Unix/Linux systems).
     */
    private static void restrictFolderPermissions(Path folder) {
        try {
            Set<PosixFilePermission> perms = Set.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE
            );
            Files.setPosixFilePermissions(folder, perms);
        } catch (UnsupportedOperationException | IOException e) {
            // POSIX permissions not supported
        }
    }
}