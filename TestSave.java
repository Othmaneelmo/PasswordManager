import com.passwordmanager.security.HashedPassword;
import com.passwordmanager.security.PBKDF2Hasher;
import com.passwordmanager.storage.VaultStorage;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class TestSave {
    public static void main(String[] args) throws IOException {
        System.out.println("Testing saveMasterKey...");

        char[] pwd = "testpassword".toCharArray();
        try {
            HashedPassword hp = PBKDF2Hasher.defaultHashPassword(pwd);

            System.out.println("Before save, exists: " + VaultStorage.exists());

            VaultStorage.saveMasterKey(hp.getAlgorithm(), hp.getIterations(), hp.getSalt(), hp.getHash());

            System.out.println("After save, exists: " + VaultStorage.exists());

            HashedPassword loaded = VaultStorage.loadHashedPassword();
            if (loaded != null) {
                System.out.println("Loaded successfully: " + loaded.getAlgorithm());
            } else {
                System.out.println("Failed to load");
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("Error: " + e.getMessage());
        }

        Arrays.fill(pwd, ' ');
    }
}
