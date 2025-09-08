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

    // Check if a vault file already exists
    public static boolean exists() {
        return Files.exists(masterKeyFile);
    }

    // Save master key hash + salt + iterations
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

    // Load stored hash data
    public static String loadMasterKey() throws IOException {
        if (!Files.exists(masterKeyFile)) {
            return null;
        }
        return Files.readString(masterKeyFile).trim();
    }

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
