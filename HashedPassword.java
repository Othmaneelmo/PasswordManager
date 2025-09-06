/*
 * Immutable data holder (POJO) for a hashed password.
 *
 * Stores all parameters needed to later verify a password:
 *  - algorithm: which KDF was used (e.g., PBKDF2WithHmacSHA256)
 *  - iterations: number of iterations (work factor)
 *  - salt: Base64-encoded random salt
 *  - hash: Base64-encoded derived key
 *
 * This ensures that every stored password carries enough context
 * for verification, even if algorithm or iteration defaults change
 * in the future.
 */
public class HashedPassword {
    private final String algorithm;
    private final int iterations;
    private final String salt;
    private final String hash;

    public HashedPassword(String algorithm, int iterations, String salt, String hash){
        this.algorithm = algorithm;
        this.iterations = iterations;
        this.salt = salt;
        this.hash = hash;
    }

    public String getAlgorithm(){
        return algorithm;
    }
    public int getIterations(){
        return iterations;
    }
    public String getSalt() {
        return salt;
    }
    public String getHash() {
        return hash;
    }
}
