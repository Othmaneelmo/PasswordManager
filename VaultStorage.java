/*
 * This class should help saving the generated masker key hash
 */
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class VaultStorage {
    private static final Path vaultFolder = Path.of("Vault");   // base folder
    private static final Path masterKeyFile = vaultFolder.resolve("masterKey.json"); // file path
    // private static final Path otherFile = vaultFolder.resolve("other.json"); // optional future files

    // Save master key hash + salt + iterations
    public static void saveMasterKey(String algorithm, int iterations, String salt, String hash) throws IOException {
        // Ensure Vault folder exists
        if (!Files.exists(vaultFolder)) {
            Files.createDirectories(vaultFolder);
        }

        // Build minimal JSON string manually (no library yet)
        String json = String.format(
            "{ \"algorithm\": \"%s\", \"iterations\": %d, \"salt\": \"%s\", \"hash\": \"%s\" }",
            algorithm, iterations, salt, hash
        );

        // Write JSON to file
        Files.writeString(masterKeyFile, json);
    }

    // Load stored hash data
    public static String loadMasterKey() throws IOException {
        if (!Files.exists(masterKeyFile)) {
            return null;
        }
        return Files.readString(masterKeyFile).trim();
    }

    // Check if a vault file already exists
    public static boolean exists() {
        return Files.exists(masterKeyFile);
    }
}
