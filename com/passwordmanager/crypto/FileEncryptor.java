package com.passwordmanager.crypto;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Streaming file encryption using authenticated encryption.
 * <p>
 * <b>Design Principles:</b>
 * </p>
 * <ul>
 *   <li><b>Streaming</b> - processes files in chunks, constant memory usage</li>
 *   <li><b>Authenticated</b> - detects tampering via AEAD</li>
 *   <li><b>Self-describing</b> - embeds all metadata needed for decryption</li>
 *   <li><b>Fail-safe</b> - cleans up on errors, no partial files</li>
 * </ul>
 * 
 * <p><b>Memory Usage:</b></p>
 * <p>
 * Uses 64KB buffers regardless of file size. Can encrypt gigabyte files
 * with minimal memory footprint.
 * </p>
 * 
 * <p><b>Security Guarantees:</b></p>
 * <ul>
 *   <li>Unique IV per file (never reused)</li>
 *   <li>Authentication tag verified on decryption</li>
 *   <li>No plaintext left on disk on failure</li>
 *   <li>Atomic write - output only completed on success</li>
 * </ul>
 */
public final class FileEncryptor {
    // Buffer size for streaming (64KB - good balance of performance/memory)
    private static final int BUFFER_SIZE = 64 * 1024;
    
    private final SecurityProfile profile;
    private final SecureRandom secureRandom;
    
    /**
     * Constructs a file encryptor with the specified security profile.
     *
     * @param profile security profile for encryption
     * @throws IllegalArgumentException if profile is null or not AES-GCM
     */
    public FileEncryptor(SecurityProfile profile) {
        if (profile == null) {
            throw new IllegalArgumentException("Security profile cannot be null");
        }
        if (!profile.getTransformation().startsWith("AES/GCM/")) {
            throw new IllegalArgumentException(
                "FileEncryptor only supports AES-GCM profiles"
            );
        }
        
        this.profile = profile;
        this.secureRandom = new SecureRandom();
    }
    
    /**
     * Encrypts a file using streaming authenticated encryption.
     * <p>
     * <b>Process:</b>
     * </p>
     * <ol>
     *   <li>Generate unique IV</li>
     *   <li>Write encrypted file header</li>
     *   <li>Stream plaintext through cipher</li>
     *   <li>Append authentication tag</li>
     *   <li>Atomically replace output file</li>
     * </ol>
     * <p>
     * <b>Atomicity:</b> Writes to temporary file first, then renames on success.
     * If encryption fails, no partial output is left.
     * </p>
     *
     * @param inputFile plaintext file to encrypt
     * @param outputFile encrypted output file
     * @param sessionKey vault session key for encryption
     * @return true if encryption succeeded
     * @throws IOException if file I/O fails
     * @throws GeneralSecurityException if encryption fails
     * @throws IllegalArgumentException if files are invalid or key is wrong
     */
    public boolean encryptFile(File inputFile, File outputFile, SecretKey sessionKey) 
            throws IOException, GeneralSecurityException {
        
        // Validate inputs
        validateEncryptInputs(inputFile, outputFile, sessionKey);
        
        // Generate unique IV
        byte[] iv = generateIv();
        
        // Derive appropriate key size
        SecretKey aesKey = deriveAesKey(sessionKey);
        
        // Use temporary file for atomic write
        File tempFile = new File(outputFile.getAbsolutePath() + ".tmp");
        
        try {
            // Write encrypted data to temp file
            encryptToStream(inputFile, tempFile, aesKey, iv);
            
            // Atomic rename (on success only)
            if (!tempFile.renameTo(outputFile)) {
                throw new IOException("Failed to rename temporary file to output file");
            }
            
            return true;
            
        } catch (Exception e) {
            // Cleanup temp file on failure
            if (tempFile.exists()) {
                tempFile.delete();
            }
            throw e;
            
        } finally {
            // Zeroize sensitive material
            zeroizeKey(aesKey);
            Arrays.fill(iv, (byte) 0);
        }
    }
    
    /**
     * Core streaming encryption logic.
     */
    private void encryptToStream(File inputFile, File outputFile, 
                                  SecretKey aesKey, byte[] iv) 
            throws IOException, GeneralSecurityException {
        
        try (InputStream plainIn = new BufferedInputStream(
                new FileInputStream(inputFile), BUFFER_SIZE);
             OutputStream encOut = new BufferedOutputStream(
                new FileOutputStream(outputFile), BUFFER_SIZE)) {
            
            // Write header
            EncryptedFileFormat.writeHeader(encOut, profile, iv);
            
            // Initialize cipher
            Cipher cipher = Cipher.getInstance(profile.getTransformation());
            GCMParameterSpec spec = new GCMParameterSpec(profile.getTagBits(), iv);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);
            
            // Stream encryption using CipherOutputStream
            try (CipherOutputStream cipherOut = new CipherOutputStream(encOut, cipher)) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;
                
                while ((bytesRead = plainIn.read(buffer)) != -1) {
                    cipherOut.write(buffer, 0, bytesRead);
                }
                
                // Ensure cipher finalization (writes auth tag)
                cipherOut.flush();
            }
            
            encOut.flush();
        }
    }
    
    /**
     * Encrypts file with progress callback.
     * <p>
     * Useful for UI integration - reports encryption progress.
     * </p>
     *
     * @param inputFile plaintext file
     * @param outputFile encrypted file
     * @param sessionKey vault session key
     * @param progressCallback called with (bytesProcessed, totalBytes)
     * @return true on success
     */
    public boolean encryptFileWithProgress(File inputFile, File outputFile, 
                                           SecretKey sessionKey,
                                           ProgressCallback progressCallback) 
            throws IOException, GeneralSecurityException {
        
        validateEncryptInputs(inputFile, outputFile, sessionKey);
        
        byte[] iv = generateIv();
        SecretKey aesKey = deriveAesKey(sessionKey);
        File tempFile = new File(outputFile.getAbsolutePath() + ".tmp");
        
        long totalBytes = inputFile.length();
        long processedBytes = 0;
        
        try {
            try (InputStream plainIn = new BufferedInputStream(
                    new FileInputStream(inputFile), BUFFER_SIZE);
                 OutputStream encOut = new BufferedOutputStream(
                    new FileOutputStream(tempFile), BUFFER_SIZE)) {
                
                EncryptedFileFormat.writeHeader(encOut, profile, iv);
                
                Cipher cipher = Cipher.getInstance(profile.getTransformation());
                GCMParameterSpec spec = new GCMParameterSpec(profile.getTagBits(), iv);
                cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);
                
                try (CipherOutputStream cipherOut = new CipherOutputStream(encOut, cipher)) {
                    byte[] buffer = new byte[BUFFER_SIZE];
                    int bytesRead;
                    
                    while ((bytesRead = plainIn.read(buffer)) != -1) {
                        cipherOut.write(buffer, 0, bytesRead);
                        processedBytes += bytesRead;
                        
                        if (progressCallback != null) {
                            progressCallback.onProgress(processedBytes, totalBytes);
                        }
                    }
                    
                    cipherOut.flush();
                }
                
                encOut.flush();
            }
            
            if (!tempFile.renameTo(outputFile)) {
                throw new IOException("Failed to rename temporary file");
            }
            
            return true;
            
        } catch (Exception e) {
            if (tempFile.exists()) {
                tempFile.delete();
            }
            throw e;
            
        } finally {
            zeroizeKey(aesKey);
            Arrays.fill(iv, (byte) 0);
        }
    }
    
    /**
     * Generates a cryptographically random IV.
     */
    private byte[] generateIv() {
        byte[] iv = new byte[profile.getIvBytes()];
        secureRandom.nextBytes(iv);
        return iv;
    }
    
    /**
     * Derives AES key from session key (handles key size adaptation).
     */
    private SecretKey deriveAesKey(SecretKey sessionKey) {
        byte[] sessionKeyBytes = sessionKey.getEncoded();
        
        if (sessionKeyBytes == null || sessionKeyBytes.length != 32) {
            throw new IllegalArgumentException(
                "Session key must be 32 bytes (256 bits)"
            );
        }
        
        int requiredBytes = profile.getKeyBytes();
        byte[] aesKeyBytes;
        
        if (requiredBytes == 32) {
            aesKeyBytes = Arrays.copyOf(sessionKeyBytes, 32);
        } else if (requiredBytes == 16) {
            aesKeyBytes = Arrays.copyOf(sessionKeyBytes, 16);
        } else {
            throw new IllegalStateException("Unsupported key size: " + requiredBytes);
        }
        
        Arrays.fill(sessionKeyBytes, (byte) 0);
        return new javax.crypto.spec.SecretKeySpec(aesKeyBytes, "AES");
    }
    
    /**
     * Zeroizes key material.
     */
    private void zeroizeKey(SecretKey key) {
        if (key == null) return;
        byte[] encoded = key.getEncoded();
        if (encoded != null) {
            Arrays.fill(encoded, (byte) 0);
        }
    }
    
    /**
     * Validates encryption inputs.
     */
    private void validateEncryptInputs(File inputFile, File outputFile, 
                                       SecretKey sessionKey) {
        if (inputFile == null) {
            throw new IllegalArgumentException("Input file cannot be null");
        }
        if (outputFile == null) {
            throw new IllegalArgumentException("Output file cannot be null");
        }
        if (sessionKey == null) {
            throw new IllegalArgumentException("Session key cannot be null");
        }
        if (!inputFile.exists()) {
            throw new IllegalArgumentException("Input file does not exist: " + 
                inputFile.getAbsolutePath());
        }
        if (!inputFile.canRead()) {
            throw new IllegalArgumentException("Cannot read input file: " + 
                inputFile.getAbsolutePath());
        }
        if (inputFile.length() == 0) {
            throw new IllegalArgumentException("Input file is empty");
        }
        if (outputFile.exists()) {
            throw new IllegalArgumentException("Output file already exists: " + 
                outputFile.getAbsolutePath());
        }
    }
    
    /**
     * Callback interface for encryption progress reporting.
     */
    @FunctionalInterface
    public interface ProgressCallback {
        void onProgress(long bytesProcessed, long totalBytes);
    }
    
    /**
     * Returns the security profile used by this encryptor.
     */
    public SecurityProfile getProfile() {
        return profile;
    }
}
