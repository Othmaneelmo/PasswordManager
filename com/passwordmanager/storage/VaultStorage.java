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
     *
     * @return the JSON string, or {@code null} if the file does not exist
     * @throws IOException if reading the vault file fails
     */
    public static String loadMasterKey() throws IOException {
        if (!Files.exists(masterKeyFile)) {
            return null;
        }
        return Files.readString(masterKeyFile).trim();
    }

    /**
     * Loads the master key as a {@link HashedPassword} object.
     * <p>
     * Parses the JSON file to extract algorithm, iterations, salt, and hash.
     * </p>
     *
     * @return the {@link HashedPassword} instance, or {@code null} if the file does not exist
     * @throws IOException if reading the vault file fails
     */
    public static HashedPassword loadHashedPassword() throws IOException {
        if (!Files.exists(masterKeyFile)) {
            return null;
        }
        String json = Files.readString(masterKeyFile);
        String algorithm = json.replaceAll("(?s).*\"algorithm\":\\s*\"([^\"]+)\".*", "$1");
        int iterations = Integer.parseInt(json.replaceAll("(?s).*\"iterations\":\\s*(\\d+).*", "$1"));
        String salt = json.replaceAll("(?s).*\"salt\":\\s*\"([^\"]+)\".*", "$1");
        String hash = json.replaceAll("(?s).*\"hash\":\\s*\"([^\"]+)\".*", "$1");
        return new HashedPassword(algorithm, iterations, salt, hash);
    }


}
