/**
 * Immutable data holder for a hashed password.
 * <p>
 * Encapsulates all information required to verify a password securely:
 * </p>
 * <ul>
 *     <li>{@code algorithm} – the key derivation function used (e.g., PBKDF2WithHmacSHA256)</li>
 *     <li>{@code iterations} – the number of iterations applied by the KDF</li>
 *     <li>{@code salt} – Base64-encoded random salt</li>
 *     <li>{@code hash} – Base64-encoded derived key</li>
 * </ul>
 * <p>
 * This ensures each stored password contains all context needed for verification,
 * even if algorithm defaults or iteration counts change in the future.
 * Instances of this class are immutable.
 * </p>
 */
public class HashedPassword {
    private final String algorithm;
    private final int iterations;
    private final String salt;
    private final String hash;

    /**
     * Constructs a new {@code HashedPassword} instance with the specified parameters.
     *
     * @param algorithm  the key derivation algorithm used
     * @param iterations the number of iterations applied in the KDF
     * @param salt       the Base64-encoded random salt
     * @param hash       the Base64-encoded derived key
     */
    public HashedPassword(String algorithm, int iterations, String salt, String hash){
        this.algorithm = algorithm;
        this.iterations = iterations;
        this.salt = salt;
        this.hash = hash;
    }

    /**
     * Returns the key derivation algorithm used.
     *
     * @return the algorithm name
     */
    public String getAlgorithm(){
        return algorithm;
    }

    /**
     * Returns the number of iterations applied in the KDF.
     *
     * @return the iteration count
     */
    public int getIterations(){
        return iterations;
    }

    /**
     * Returns the Base64-encoded random salt.
     *
     * @return the salt
     */
    public String getSalt() {
        return salt;
    }

    /**
     * Returns the Base64-encoded derived key (hash).
     *
     * @return the hashed password
     */
    public String getHash() {
        return hash;
    }
}
