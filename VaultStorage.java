/*
 * This class should help saving the generated masker key hash
 */

import java.io.IOException;

public class VaultStorage {
    private static final String FILE_NAME = "vault.json";

    // Save master key hash + salt + iterations
    public static void saveMasterKey(String algorithm, int iterations, String salt, String hash) throws IOException {
        // TODO: implement saving to JSON file
    }

    // Load stored hash data
    public static String loadMasterKey() throws IOException {
        // TODO: implement reading from JSON file
        return null;
    }

    // Check if a vault file already exists
    public static boolean exists() {
        // TODO: implement file existence check
        return false;
    }