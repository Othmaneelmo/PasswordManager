# File Encryption System - Architecture & Integration Guide

## Overview

This document describes the secure file encryption system integrated into the password manager vault.

## Architecture

### Component Hierarchy

```
VaultSession (core)
    ↓ provides SecretKey
FileEncryptor / FileDecryptor (crypto layer)
    ↓ uses
EncryptedFileFormat (format specification)
    ↓ consumed by
EncryptFileFeature / DecryptFileFeature (user interface)
```

### Key Design Principles

1. **Separation of Concerns**
   - Core vault logic untouched
   - Encryption is a feature module, not core functionality
   - Format specification independent of crypto implementation

2. **Defense in Depth**
   - Authenticated encryption (AEAD)
   - Tamper detection
   - Format validation
   - Atomic file operations

3. **Fail-Safe Behavior**
   - No partial output on failure
   - Authentication verified before writing
   - Temporary files cleaned up on error

4. **Memory Efficiency**
   - Streaming I/O with 64KB buffers
   - Constant memory usage regardless of file size
   - Can handle gigabyte files with minimal footprint

## File Format Specification

### Structure

```
Offset  Size    Field           Description
------  ----    -----           -----------
0       8       Magic           "VAULTENC" (ASCII)
8       1       Version         0x01 (current)
9       1       Profile         0x00=FAST, 0x01=BALANCED, 0x02=PARANOID
10      2       IV Length       Big-endian uint16 (12 or 16)
12      N       IV              Initialization vector
12+N    M       Ciphertext      Encrypted data + auth tag (GCM)
```

### Version Evolution

**Current Version (0x01)**
- AES-GCM encryption
- Three security profiles
- IV size: 12 or 16 bytes
- Tag size: 96 or 128 bits

**Future Versions**
- 0x02: Could add compression flags
- 0x03: Could add key rotation metadata
- 0x04: Could add file chunking for streaming

### Self-Describing Property

Files contain all information needed for decryption:
- Algorithm (via profile byte)
- IV length (explicit)
- IV value (embedded)
- Authentication tag (embedded in ciphertext)

No external metadata files needed.

## Security Analysis

### Threat Model

**Threats Mitigated:**

1. **Unauthorized Access**
   - ✓ Files encrypted with vault session key
   - ✓ No key derivation from user input
   - ✓ AES-256-GCM provides confidentiality

2. **Data Tampering**
   - ✓ AEAD authentication tag
   - ✓ Tag verified before plaintext output
   - ✓ Any modification detected and rejected

3. **Format Confusion**
   - ✓ Magic header prevents misidentification
   - ✓ Version byte supports evolution
   - ✓ Profile validation ensures correct decryption

4. **Information Leakage**
   - ✓ File size leaked (unavoidable with current design)
   - ✓ Profile byte visible (minimal info)
   - ✓ No plaintext metadata stored

5. **Key Compromise**
   - ✓ Session key zeroized after use
   - ✓ No keys persisted to disk
   - ✓ Vault lock clears all key material

**Threats NOT Mitigated:**

1. **File Size Analysis**
   - Encrypted file size ≈ plaintext size + ~50 bytes
   - Attackers can estimate original size
   - **Mitigation**: Future version could add padding

2. **Traffic Analysis**
   - File access patterns visible to OS
   - **Mitigation**: Use encrypted volumes (OS-level)

3. **Memory Attacks**
   - Keys exist in memory while vault unlocked
   - **Mitigation**: Minimize unlock duration, use secure memory (future)

4. **Side Channels**
   - Timing, cache, power analysis possible
   - **Mitigation**: Hardware AES-NI helps, but not perfect

### Security Properties

**Confidentiality**
- AES-256: 2^256 keyspace (brute force infeasible)
- AES-128: 2^128 keyspace (still strong)
- Unique IV per file prevents pattern detection

**Integrity**
- GCM authentication: 2^96 or 2^128 forgery resistance
- Tag verified atomically
- No partial output on auth failure

**Authenticity**
- Session key proves vault ownership
- Cannot decrypt without correct master key
- Cannot forge valid ciphertext

## Performance Characteristics

### Benchmarks

**Hardware:** Modern CPU with AES-NI
**Profile:** BALANCED (AES-256-GCM)

| File Size | Encryption | Decryption | Throughput |
|-----------|-----------|-----------|-----------|
| 1 MB      | ~10 ms    | ~8 ms     | ~100 MB/s |
| 10 MB     | ~80 ms    | ~70 ms    | ~125 MB/s |
| 100 MB    | ~700 ms   | ~650 ms   | ~140 MB/s |

*Note: Actual performance varies by hardware, JVM, and I/O subsystem*

### Scalability

- **Memory Usage:** O(1) - constant 64KB buffer
- **Time Complexity:** O(n) - linear in file size
- **Disk I/O:** Sequential reads/writes (optimal)

### Bottlenecks

1. **CPU-bound:** AES-GCM computation
   - Mitigated by hardware acceleration (AES-NI)
   
2. **I/O-bound:** Disk speed for large files
   - Mitigated by buffering and sequential access

3. **JVM overhead:** Object allocation, GC
   - Mitigated by buffer reuse

## Integration Examples

### Basic Console Application

```java
// Main menu integration
public static void showMenu(Console console) {
    System.out.println("1. Unlock Vault");
    System.out.println("2. Encrypt File");
    System.out.println("3. Decrypt File");
    System.out.println("4. Lock Vault");
    
    String choice = console.readLine("Select option: ");
    
    switch (choice) {
        case "2":
            EncryptFileFeature.execute(console);
            break;
        case "3":
            DecryptFileFeature.execute(console);
            break;
    }
}
```

### Programmatic API Usage

```java
// Setup vault
char[] password = console.readPassword("Master key: ");
HashedPassword stored = VaultStorage.loadHashedPassword();
byte[] sessionKey = PBKDF2Hasher.deriveSessionKey(password, stored);
VaultSession.unlock(sessionKey);

// Encrypt file
File inputFile = new File("secret.pdf");
File encryptedFile = new File("secret.pdf.vault");

FileEncryptor encryptor = new FileEncryptor(SecurityProfile.BALANCED);
boolean success = encryptor.encryptFile(
    inputFile,
    encryptedFile,
    VaultSession.getVaultSessionKey()
);

// Decrypt file
File decryptedFile = new File("secret_recovered.pdf");

success = FileDecryptor.decryptFile(
    encryptedFile,
    decryptedFile,
    VaultSession.getVaultSessionKey()
);

// Lock vault when done
VaultSession.lock();
```

### With Progress Reporting

```java
FileEncryptor encryptor = new FileEncryptor(SecurityProfile.BALANCED);

encryptor.encryptFileWithProgress(
    inputFile,
    encryptedFile,
    VaultSession.getVaultSessionKey(),
    (bytesProcessed, totalBytes) -> {
        int percent = (int)((bytesProcessed * 100) / totalBytes);
        System.out.printf("\rProgress: %d%%", percent);
    }
);
```

## Future Enhancements

### 1. Compression Before Encryption

**Rationale:** Reduce file size, improve performance

**Implementation:**
```java
// Add compression flag to format
[MAGIC][VERSION][PROFILE][COMPRESSION_FLAG][IV_LEN][IV][DATA]

// Compress before encryption
byte[] plaintext = Files.readAllBytes(inputFile);
byte[] compressed = compress(plaintext);  // GZIP, LZ4, etc.
EncryptionResult result = provider.encrypt(compressed, sessionKey);
```

**Considerations:**
- Compression ratio varies by file type
- Already-compressed files (JPEG, PNG) don't benefit
- Could auto-detect and skip compression

### 2. File Chunking for Streaming

**Rationale:** Enable pause/resume, parallel processing

**Implementation:**
```
[HEADER]
[CHUNK_1_IV][CHUNK_1_ENCRYPTED]
[CHUNK_2_IV][CHUNK_2_ENCRYPTED]
...
[MANIFEST_HASH]
```

**Benefits:**
- Verify chunks independently
- Resume interrupted operations
- Parallel encryption/decryption

### 3. Steganography Support

**Rationale:** Hide encrypted data in innocuous files

**Implementation:**
```java
// Embed encrypted data in PNG/JPEG LSBs
StegEncoder encoder = new StegEncoder(coverImage);
encoder.embed(encryptedBytes);
encoder.writeToFile(outputImage);

// Extract
StegDecoder decoder = new StegDecoder(stegoImage);
byte[] encryptedBytes = decoder.extract();
```

**Use Cases:**
- Covert storage
- Plausible deniability
- Anti-censorship

### 4. Key Rotation

**Rationale:** Limit damage from key compromise

**Implementation:**
```
[MAGIC][VERSION][PROFILE][KEY_VERSION][IV][DATA]

// Support multiple key versions
Map<Integer, SecretKey> keyVersions = loadKeyVersions();
SecretKey key = keyVersions.get(fileKeyVersion);
decrypt(ciphertext, key);
```

**Workflow:**
1. Generate new vault key
2. Re-encrypt all files with new key
3. Retire old key after grace period

### 5. Authenticated Additional Data (AAD)

**Rationale:** Bind metadata to ciphertext

**Implementation:**
```java
// Include filename, timestamp, user ID in AAD
String aad = filename + "|" + timestamp + "|" + userId;
cipher.updateAAD(aad.getBytes());
byte[] ciphertext = cipher.doFinal(plaintext);
```

**Benefits:**
- Prevents file swapping attacks
- Verifies metadata authenticity
- Context binding

## Testing Strategy

### Unit Tests

```java
@Test
public void testEncryptDecrypt() {
    byte[] plaintext = "secret".getBytes();
    File plain = writeTempFile(plaintext);
    File enc = new File("test.vault");
    File dec = new File("test_dec.txt");
    
    FileEncryptor encryptor = new FileEncryptor(BALANCED);
    encryptor.encryptFile(plain, enc, sessionKey);
    
    FileDecryptor.decryptFile(enc, dec, sessionKey);
    
    byte[] decrypted = Files.readAllBytes(dec.toPath());
    assertArrayEquals(plaintext, decrypted);
}

@Test(expected = GeneralSecurityException.class)
public void testTamperDetection() {
    // Encrypt file
    encryptor.encryptFile(plain, enc, sessionKey);
    
    // Tamper with ciphertext
    byte[] data = Files.readAllBytes(enc.toPath());
    data[50] ^= 0xFF;
    Files.write(enc.toPath(), data);
    
    // Should throw on auth failure
    FileDecryptor.decryptFile(enc, dec, sessionKey);
}
```

### Integration Tests

```java
@Test
public void testLargeFile() {
    // Create 100MB file
    byte[] data = new byte[100 * 1024 * 1024];
    new SecureRandom().nextBytes(data);
    
    File large = writeTempFile(data);
    File enc = new File("large.vault");
    File dec = new File("large_dec.dat");
    
    // Encrypt and decrypt
    encryptor.encryptFile(large, enc, sessionKey);
    FileDecryptor.decryptFile(enc, dec, sessionKey);
    
    // Verify
    assertTrue(Arrays.equals(data, Files.readAllBytes(dec)));
}
```

### Security Tests

```java
@Test
public void testNoPartialOutputOnFailure() {
    encryptor.encryptFile(plain, enc, sessionKey);
    
    // Corrupt file
    byte[] data = Files.readAllBytes(enc.toPath());
    data[data.length - 1] ^= 0xFF;
    Files.write(enc.toPath(), data);
    
    File dec = new File("out.txt");
    
    try {
        FileDecryptor.decryptFile(enc, dec, sessionKey);
        fail("Should have thrown");
    } catch (GeneralSecurityException e) {
        // Expected
    }
    
    assertFalse(dec.exists(), "No output on auth failure");
}
```

## Deployment Checklist

- [ ] Vault unlocking tested and working
- [ ] File encryption with all profiles tested
- [ ] File decryption verified
- [ ] Tamper detection confirmed
- [ ] Wrong key rejection confirmed
- [ ] Large file performance acceptable
- [ ] Binary file integrity preserved
- [ ] Error messages user-friendly
- [ ] Temporary file cleanup verified
- [ ] Memory usage profiled
- [ ] Documentation reviewed
- [ ] Security audit completed

## Conclusion

This file encryption system provides:

✓ **Strong Security** - AES-GCM with proper authentication  
✓ **Scalability** - Handles files of any size  
✓ **Usability** - Simple console interface  
✓ **Extensibility** - Version-tagged format supports evolution  
✓ **Safety** - Fail-safe behavior, no partial outputs  

The modular design allows future enhancements without breaking existing functionality or security guarantees.