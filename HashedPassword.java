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
