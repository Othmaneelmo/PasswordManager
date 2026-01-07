package com.passwordmanager.storage;
import com.passwordmanager.security.HashedPassword;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Handles persistent storage for the vault, including saving and loading the master key hash.
 * <p>
 * The vault is stored under a dedicated folder ("Vault") and uses a JSON file to persist 
 * the master key's algorithm, iterations, salt, and hash. Future expansions can add additional
 * files for account data or encrypted storage.
 * </p>
 */
public class VaultStorage {
    private static final Path vaultFolder = Path.of("Vault");   // base folder
    private static final Path masterKeyFile = vaultFolder.resolve("masterKey.json"); // file path
    // private static final Path otherFile = vaultFolder.resolve("other.json"); // optional future files

    /**
     * Checks whether the vault already exists.
     *
     * @return {@code true} if the master key file exists, {@code false} otherwise
     */
    public static boolean exists() {
        return Files.exists(masterKeyFile);
    }

    /**
     * Saves the master key's PBKDF2 parameters and hash to persistent storage.
     * <p>
     * Creates the vault folder if it does not exist. The JSON structure is manually built.
     * </p>
     *
     * @param algorithm  the key derivation algorithm used
     * @param iterations the number of PBKDF2 iterations
     * @param salt       the Base64-encoded random salt
     * @param hash       the Base64-encoded derived key
     * @throws IOException if writing to the vault file fails
     */
    public static void saveMasterKey(String algorithm, int iterations, String salt, String hash) throws IOException {
        // Ensure Vault folder exists
        if (!Files.exists(vaultFolder)) {
            Files.createDirectories(vaultFolder);
        }

        // Build minimal JSON string manually (no library yet)
        String json = String.format(
            "{\n" +
            "  \"algorithm\": \"%s\",\n" +
            "  \"iterations\": %d,\n" +
            "  \"salt\": \"%s\",\n" +
            "  \"hash\": \"%s\"\n" +
            "}",
            algorithm, iterations, salt, hash
        );

        // Write JSON to file
        Files.writeString(masterKeyFile, json);
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
