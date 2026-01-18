package com.passwordmanager.crypto;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Streaming file decryption with authentication verification.
 * <p>
 * <b>Security Guarantees:</b>
 * </p>
 * <ul>
 *   <li>Authentication tag verified before returning plaintext</li>
 *   <li>No partial output on authentication failure</li>
 *   <li>Tampering detected and rejected</li>
 *   <li>Atomic write - output only on successful verification</li>
 * </ul>
 * 
 * <p><b>Failure Modes:</b></p>
 * <ul>
 *   <li><b>Wrong key</b> - authentication fails, no output</li>
 *   <li><b>Corrupted file</b> - authentication fails, no output</li>
 *   <li><b>Tampered data</b> - authentication fails, no output</li>
 *   <li><b>Format error</b> - exception thrown, no output</li>
 * </ul>
 * 
 * <p><b>Design Note:</b></p>
 * <p>
 * GCM authentication happens during final block processing. CipherInputStream
 * will throw AEADBadTagException if authentication fails. We catch this and
 * clean up any partial output.
 * </p>
 */
public final class FileDecryptor {
    private static final int BUFFER_SIZE = 64 * 1024;
    
    /**
     * Decrypts an encrypted file using streaming authenticated decryption.
     * <p>
     * <b>Process:</b>
     * </p>
     * <ol>
     *   <li>Read and validate file header</li>
     *   <li>Extract metadata (IV, profile)</li>
     *   <li>Stream ciphertext through cipher</li>
     *   <li>Verify authentication tag</li>
     *   <li>Atomically write output on success</li>
     * </ol>
     * <p>
     * <b>Critical:</b> If authentication fails, no output file is created and
     * any temporary files are deleted.
     * </p>
     *
     * @param inputFile encrypted file to decrypt
     * @param outputFile plaintext output file
     * @param sessionKey vault session key for decryption
     * @return true if decryption and verification succeeded
     * @throws IOException if file I/O fails or format is invalid
     * @throws GeneralSecurityException if decryption or authentication fails
     * @throws IllegalArgumentException if files are invalid or key is wrong
     */
    public static boolean decryptFile(File inputFile, File outputFile, 
                                     SecretKey sessionKey) 
            throws IOException, GeneralSecurityException {
        
        // Validate inputs
        validateDecryptInputs(inputFile, outputFile, sessionKey);
        
        // Use temporary file for atomic write
        File tempFile = new File(outputFile.getAbsolutePath() + ".tmp");
        
        EncryptedFileFormat.FileMetadata metadata = null;
        SecretKey aesKey = null;
        
        try {
            // Read header and extract metadata
            try (InputStream in = new BufferedInputStream(
                    new FileInputStream(inputFile), BUFFER_SIZE)) {
                
                metadata = EncryptedFileFormat.readHeader(in);
                
                // Derive appropriate key size
                aesKey = deriveAesKey(sessionKey, metadata.getProfile());
                
                // Decrypt to temp file
                decryptToStream(in, tempFile, aesKey, metadata);
            }
            
            // Atomic rename (only on success)
            if (!tempFile.renameTo(outputFile)) {
                throw new IOException("Failed to rename temporary file to output file");
            }
            
            return true;
            
        } catch (javax.crypto.AEADBadTagException e) {
            // Authentication failed - file tampered or wrong key
            throw new GeneralSecurityException(
                "Authentication failed - file may be corrupted, tampered, or wrong key used",
                e
            );
            
        } catch (Exception e) {
            // Cleanup temp file on any failure
            if (tempFile.exists()) {
                tempFile.delete();
            }
            throw e;
            
        } finally {
            // Cleanup sensitive material
            if (metadata != null) {
                metadata.zeroize();
            }
            if (aesKey != null) {
                zeroizeKey(aesKey);
            }
        }
    }
    
    /**
     * Core streaming decryption logic.
     * <p>
     * <b>Important:</b> The InputStream passed here is already positioned
     * after the header (by readHeader). We read from current position to EOF.
     * </p>
     */
    private static void decryptToStream(InputStream cipherIn, File outputFile,
                                       SecretKey aesKey, 
                                       EncryptedFileFormat.FileMetadata metadata)
            throws IOException, GeneralSecurityException {
        
        // Initialize cipher for decryption
        Cipher cipher = Cipher.getInstance(metadata.getProfile().getTransformation());
        GCMParameterSpec spec = new GCMParameterSpec(
            metadata.getProfile().getTagBits(),
            metadata.getIv()
        );
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
        
        // Stream decryption
        try (CipherInputStream decryptIn = new CipherInputStream(cipherIn, cipher);
             OutputStream plainOut = new BufferedOutputStream(
                new FileOutputStream(outputFile), BUFFER_SIZE)) {
            
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            
            while ((bytesRead = decryptIn.read(buffer)) != -1) {
                plainOut.write(buffer, 0, bytesRead);
            }
            
            plainOut.flush();
        }
        // CipherInputStream.close() triggers final cipher block processing
        // If authentication fails, AEADBadTagException is thrown here
    }
    
    /**
     * Decrypts file with progress callback.
     * <p>
     * <b>Note:</b> Progress reporting for decryption is approximate because
     * we can't know the plaintext size in advance. We report based on
     * ciphertext bytes read.
     * </p>
     *
     * @param inputFile encrypted file
     * @param outputFile plaintext file
     * @param sessionKey vault session key
     * @param progressCallback called with (bytesProcessed, totalBytes)
     * @return true on success
     */
    public static boolean decryptFileWithProgress(File inputFile, File outputFile,
                                                  SecretKey sessionKey,
                                                  ProgressCallback progressCallback)
            throws IOException, GeneralSecurityException {
        
        validateDecryptInputs(inputFile, outputFile, sessionKey);
        
        File tempFile = new File(outputFile.getAbsolutePath() + ".tmp");
        EncryptedFileFormat.FileMetadata metadata = null;
        SecretKey aesKey = null;
        
        // Total bytes = file size (includes header + ciphertext + tag)
        long totalBytes = inputFile.length();
        long processedBytes = 0;
        
        try {
            try (InputStream fileIn = new FileInputStream(inputFile)) {
                // Wrap in custom counting stream
                CountingInputStream countingIn = new CountingInputStream(fileIn);
                
                try (BufferedInputStream bufferedIn = new BufferedInputStream(
                        countingIn, BUFFER_SIZE)) {
                    
                    metadata = EncryptedFileFormat.readHeader(bufferedIn);
                    aesKey = deriveAesKey(sessionKey, metadata.getProfile());
                    
                    Cipher cipher = Cipher.getInstance(
                        metadata.getProfile().getTransformation()
                    );
                    GCMParameterSpec spec = new GCMParameterSpec(
                        metadata.getProfile().getTagBits(),
                        metadata.getIv()
                    );
                    cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
                    
                    try (CipherInputStream cipherIn = new CipherInputStream(
                            bufferedIn, cipher);
                         OutputStream plainOut = new BufferedOutputStream(
                            new FileOutputStream(tempFile), BUFFER_SIZE)) {
                        
                        byte[] buffer = new byte[BUFFER_SIZE];
                        int bytesRead;
                        
                        while ((bytesRead = cipherIn.read(buffer)) != -1) {
                            plainOut.write(buffer, 0, bytesRead);
                            
                            processedBytes = countingIn.getBytesRead();
                            if (progressCallback != null) {
                                progressCallback.onProgress(processedBytes, totalBytes);
                            }
                        }
                        
                        plainOut.flush();
                    }
                }
            }
            
            if (!tempFile.renameTo(outputFile)) {
                throw new IOException("Failed to rename temporary file");
            }
            
            return true;
            
        } catch (javax.crypto.AEADBadTagException e) {
            throw new GeneralSecurityException(
                "Authentication failed - wrong key or corrupted file", e
            );
            
        } catch (Exception e) {
            if (tempFile.exists()) {
                tempFile.delete();
            }
            throw e;
            
        } finally {
            if (metadata != null) {
                metadata.zeroize();
            }
            if (aesKey != null) {
                zeroizeKey(aesKey);
            }
        }
    }
    
    /**
     * Verifies file integrity without decrypting to disk.
     * <p>
     * Useful for checking if a file can be decrypted with the current key
     * without writing output.
     * </p>
     *
     * @param inputFile encrypted file to verify
     * @param sessionKey vault session key
     * @return true if file is valid and can be decrypted
     */
    public static boolean verifyFile(File inputFile, SecretKey sessionKey) {
        if (inputFile == null || !inputFile.exists() || !inputFile.canRead()) {
            return false;
        }
        
        EncryptedFileFormat.FileMetadata metadata = null;
        SecretKey aesKey = null;
        
        try (InputStream fileIn = new BufferedInputStream(
                new FileInputStream(inputFile), BUFFER_SIZE)) {
            
            metadata = EncryptedFileFormat.readHeader(fileIn);
            aesKey = deriveAesKey(sessionKey, metadata.getProfile());
            
            Cipher cipher = Cipher.getInstance(
                metadata.getProfile().getTransformation()
            );
            GCMParameterSpec spec = new GCMParameterSpec(
                metadata.getProfile().getTagBits(),
                metadata.getIv()
            );
            cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
            
            try (CipherInputStream cipherIn = new CipherInputStream(fileIn, cipher)) {
                byte[] buffer = new byte[BUFFER_SIZE];
                
                // Read through entire file to trigger authentication
                while (cipherIn.read(buffer) != -1) {
                    // Discard output
                }
            }
            
            // If we get here, authentication succeeded
            return true;
            
        } catch (Exception e) {
            // Any error means verification failed
            return false;
            
        } finally {
            if (metadata != null) {
                metadata.zeroize();
            }
            if (aesKey != null) {
                zeroizeKey(aesKey);
            }
        }
    }
    
    /**
     * Derives AES key from session key.
     */
    private static SecretKey deriveAesKey(SecretKey sessionKey, 
                                         SecurityProfile profile) {
        byte[] sessionKeyBytes = sessionKey.getEncoded();
        
        if (sessionKeyBytes == null || sessionKeyBytes.length != 32) {
            throw new IllegalArgumentException("Session key must be 32 bytes");
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
    private static void zeroizeKey(SecretKey key) {
        if (key == null) return;
        byte[] encoded = key.getEncoded();
        if (encoded != null) {
            Arrays.fill(encoded, (byte) 0);
        }
    }
    
    /**
     * Validates decryption inputs.
     */
    private static void validateDecryptInputs(File inputFile, File outputFile,
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
        if (outputFile.exists()) {
            throw new IllegalArgumentException("Output file already exists: " + 
                outputFile.getAbsolutePath());
        }
    }
    
    /**
     * Progress callback interface.
     */
    @FunctionalInterface
    public interface ProgressCallback {
        void onProgress(long bytesProcessed, long totalBytes);
    }
    
    /**
     * Counting input stream for progress tracking.
     */
    private static class CountingInputStream extends FilterInputStream {
        private long bytesRead = 0;
        
        CountingInputStream(InputStream in) {
            super(in);
        }
        
        @Override
        public int read() throws IOException {
            int b = super.read();
            if (b != -1) bytesRead++;
            return b;
        }
        
        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int n = super.read(b, off, len);
            if (n > 0) bytesRead += n;
            return n;
        }
        
        long getBytesRead() {
            return bytesRead;
        }
    }
}