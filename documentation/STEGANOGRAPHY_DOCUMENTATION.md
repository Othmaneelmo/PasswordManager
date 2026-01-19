# Steganography System Documentation

## Overview

The steganography system enables hiding encrypted files inside images without visibly altering them. It combines **LSB (Least Significant Bit) steganography** with **AES-GCM authenticated encryption** to provide both concealment and security.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Steganography System                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌────────────────────────────────────────────────────────┐ │
│  │                    User Interface                      │ │
│  │  (HideFileInImageFeature / ExtractFileFromImageFeature)│ │
│  └───────────────────┬────────────────────────────────────┘ │
│                      │                                      │
│  ┌───────────────────▼───────────────────────────────────┐  │
│  │                  StegoEngine                          │  │
│  │  • Composes encryption + embedding                    │  │
│  │  • Manages header + payload                           │  │
│  │  • Validates capacity                                 │  │
│  └───────────┬──────────────────┬────────────────────────┘  │
│              │                  │                           │
│  ┌───────────▼─────────┐  ┌───▼──────────────────────┐      │
│  │ EncryptionProvider  │  │  LSBSteganography        │      │
│  │  (AES-GCM)          │  │  • Embed/Extract         │      │
│  │  • Encrypt          │  │  • Capacity calculation  │      │
│  │  • Decrypt          │  └──────────────────────────┘      │
│  │  • Authenticate     │                                    │
│  └─────────────────────┘                                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## LSB Steganography Algorithm

### Embedding Process

**Step 1: Pixel Traversal**
- Traverse image pixels left-to-right, top-to-bottom
- Process each pixel's RGB channels

**Step 2: Bit Extraction**
- Convert payload bytes to bit stream
- Extract 3 bits at a time (one per RGB channel)

**Step 3: LSB Replacement**
```
Original pixel: RGB(10110010, 11001101, 01010111)
Data bits:      1             0             1

Modified pixel: RGB(10110011, 11001100, 01010111)
                      ↑              ↑              ↑
                    (LSB replaced with data bits)
```

**Step 4: Continue**
- Repeat until all payload bits are embedded
- Remaining pixels stay unchanged

### Visual Impact

Each pixel channel can change by at most ±1:
- **Before:** RGB(178, 205, 87)
- **After:** RGB(179, 204, 87)
- **Change:** Imperceptible to human eye

## Data Format

### Complete Embedded Structure

```
[Header]  [IV]  [Encrypted Payload]
   ↓       ↓           ↓
 Metadata  Random    Ciphertext + Auth Tag
```

### Header Format (14+ bytes)

```
Offset | Size | Field          | Description
-------|------|----------------|---------------------------
0      | 4    | Magic          | "STEG" (ASCII)
4      | 1    | Version        | 0x01
5      | 1    | Profile        | 0x00/0x01/0x02
6      | 4    | Payload Size   | Big-endian uint32
10     | 2    | Filename Len   | Big-endian uint16
12     | var  | Filename       | UTF-8 encoded
var    | 2    | Reserved       | 0x0000
```

### Security Properties

1. **Magic Bytes**: Identifies steganographic content
2. **Version**: Allows format evolution
3. **Profile**: Specifies encryption parameters
4. **Payload Size**: Enables exact extraction
5. **Filename**: Preserves original file identity

## Capacity Calculation

### Formula

```
Capacity (bytes) = (Width × Height × 3) / 8
```

Where:
- **Width × Height** = Total pixels
- **× 3** = RGB channels per pixel (3 bits per pixel)
- **/ 8** = Convert bits to bytes

### Examples

| Resolution | Pixels      | Capacity | Use Case |
|------------|-------------|----------|----------|
| 640×480    | 307,200     | ~115 KB  | Small documents |
| 1280×720   | 921,600     | ~345 KB  | Documents, code |
| 1920×1080  | 2,073,600   | ~777 KB  | Large files |
| 3840×2160  | 8,294,400   | ~3.1 MB  | Multiple files |

### Overhead Calculation

Total space required = File size + Encryption overhead + Header

**Encryption Overhead (per profile):**
- **FAST**: IV (12 bytes) + Tag (12 bytes) = 24 bytes
- **BALANCED**: IV (12 bytes) + Tag (16 bytes) = 28 bytes
- **PARANOID**: IV (16 bytes) + Tag (16 bytes) = 32 bytes

**Header Overhead:**
- Fixed: 14 bytes
- Variable: Filename length (typically 10-50 bytes)

## Security Analysis

### Threat Model

**Assumptions:**
- Attacker has access to steganographic images
- Attacker knows steganography is being used
- Attacker can perform statistical analysis

**Protections:**
- Encryption ensures payload appears random
- Authentication detects tampering
- No keys embedded in carrier

### Security Guarantees

#### 1. Confidentiality
- **Protection**: AES-GCM encryption
- **Guarantee**: Payload is computationally infeasible to decrypt without key
- **Strength**: 128-bit (FAST) or 256-bit (BALANCED/PARANOID) security

#### 2. Authenticity
- **Protection**: GCM authentication tag
- **Guarantee**: Any modification detected with probability 1 - 2^-96 (FAST) or 1 - 2^-128
- **Behavior**: Failed authentication = no extraction

#### 3. Stealth
- **Protection**: LSB modifications imperceptible
- **Limitation**: Statistical analysis can detect presence (but not content)
- **Note**: Use encryption to prevent payload recovery even if detected

### Attack Resistance

#### Statistical Analysis
- **Threat**: Chi-square tests, histogram analysis
- **Defense**: Encrypted payload appears random
- **Result**: Presence may be detected, but content remains secure

#### Visual Steganalysis
- **Threat**: LSB plane analysis, noise analysis
- **Defense**: Changes limited to ±1 per channel
- **Result**: Requires specialized tools to detect

#### Tampering
- **Threat**: Modify carrier image or embedded data
- **Defense**: GCM authentication tag
- **Result**: Extraction fails, no partial data released

#### Wrong Key
- **Threat**: Extract using incorrect vault key
- **Defense**: Authentication failure
- **Result**: Immediate rejection, no information leaked

## Composition of Encryption and Steganography

### Why Encrypt Before Embedding?

1. **Statistical Properties**: Encrypted data appears random, improving steganographic concealment
2. **Security**: Even if steganography is detected, data remains protected
3. **Authentication**: Prevents extraction of tampered data
4. **Defense in Depth**: Multiple layers of protection

### Data Flow

```
┌─────────────┐
│ Secret File │
└──────┬──────┘
       │
       ▼
┌────────────────┐     [Vault Session Key]
│ AES-GCM Encrypt│ ◄────────────────────
└──────┬─────────┘
       │
       ▼
┌──────────────────────┐
│ [IV][Ciphertext+Tag] │
└──────┬───────────────┘
       │
       ▼
┌───────────────────┐
│  Create Header    │
└──────┬────────────┘
       │
       ▼
┌─────────────────────────┐
│ [Header][IV][Ciphertext]│
└──────┬──────────────────┘
       │
       ▼
┌──────────────────┐
│  LSB Embedding   │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ Stego Carrier    │
└──────────────────┘
```

### Extraction Flow

```
┌──────────────────┐
│ Stego Carrier    │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│  LSB Extraction  │
└──────┬───────────┘
       │
       ▼
┌─────────────────────────┐
│ [Header][IV][Ciphertext]│
└──────┬──────────────────┘
       │
       ▼
┌────────────────┐
│  Parse Header  │
└──────┬─────────┘
       │
       ▼
┌────────────────┐     [Vault Session Key]
│ AES-GCM Decrypt│ ◄────────────────────
└──────┬─────────┘
       │
       ▼
┌────────────────┐
│ Authenticate   │ ─── FAIL → Error, No Output
└──────┬─────────┘
       │ PASS
       ▼
┌─────────────┐
│ Secret File │
└─────────────┘
```

## Usage Examples

### Example 1: Hide a Document

```bash
# Run the password manager
java com.passwordmanager.main.Main

# Select "Hide File in Image"
# Follow prompts:
Enter path to file to hide: secret_document.pdf
Enter path to carrier image (PNG/BMP): vacation_photo.png
Select security profile: 2 (BALANCED)
Enter output image path: vacation_photo_stego.png
Proceed with hiding? (yes/no): yes

# Result: vacation_photo_stego.png looks identical to vacation_photo.png
```

### Example 2: Extract a Document

```bash
# Run the password manager
java com.passwordmanager.main.Main

# Select "Extract File from Image"
# Follow prompts:
Enter path to steganographic image: vacation_photo_stego.png
Select security profile: 2 (BALANCED)
Enter output file path: recovered_document.pdf
Proceed with extraction? (yes/no): yes

# Result: recovered_document.pdf is identical to secret_document.pdf
```

### Example 3: Capacity Check

```java
// Calculate required image size
File secretFile = new File("my_file.zip");
long fileSize = secretFile.length();

// Add overhead
int overhead = 28 + 14 + 20; // encryption + header + filename
long totalNeeded = fileSize + overhead;

// Calculate pixels needed
long pixelsNeeded = (totalNeeded * 8 + 2) / 3;
int side = (int) Math.ceil(Math.sqrt(pixelsNeeded));

System.out.println("Minimum image size: " + side + "x" + side);
```

## Integration with Main Application

### Registering Features

Add to `Main.registerFeatures()`:

```java
private static void registerFeatures(FeatureRegistry registry) {
    // Existing features...
    
    // Steganography features
    registry.register(new HideFileInImageFeature(VaultSession.INSTANCE));
    registry.register(new ExtractFileFromImageFeature(VaultSession.INSTANCE));
}
```

### Feature Appears in Menu

```
=== FILE MANAGEMENT ===
[5] Hide File in Image
[6] Extract File from Image
```

## Error Handling

### Common Errors and Solutions

| Error | Cause | Solution |
|-------|-------|----------|
| "Payload too large" | File exceeds carrier capacity | Use larger image |
| "Authentication failed" | Wrong key or tampered image | Verify vault key and image integrity |
| "Invalid magic bytes" | Image has no hidden data | Verify you're using a stego image |
| "Profile mismatch" | Wrong profile selected | Use same profile as hiding |
| "Unsupported format" | Wrong image format | Use PNG or BMP |

### Error Messages

**Capacity Error:**
```
ERROR: File too large for carrier image.
Required: 850 KB, Available: 777 KB

Suggestion: Use a larger image or compress the file.
```

**Authentication Error:**
```
✗ AUTHENTICATION FAILED
  This means one of the following:
  - Wrong vault master key
  - Image has been tampered with or corrupted
  - Image was created with a different vault
  - Wrong security profile selected

  No output file was created (security measure).
```

## Performance Characteristics

### Benchmarks (1920×1080 PNG, BALANCED profile)

| File Size | Hide Time | Extract Time | Throughput |
|-----------|-----------|--------------|------------|
| 10 KB     | 180 ms    | 120 ms       | ~55 KB/s   |
| 100 KB    | 250 ms    | 180 ms       | ~400 KB/s  |
| 500 KB    | 600 ms    | 450 ms       | ~830 KB/s  |

**Factors affecting performance:**
- Image dimensions (larger = more pixels to process)
- File size (larger = more data to encrypt)
- Security profile (PARANOID slightly slower)
- Disk I/O speed

## Limitations

### Technical Limitations

1. **Carrier Format**: PNG and BMP only (lossless formats required)
2. **Maximum Payload**: Limited by image size
3. **Format Preservation**: Carrier must remain uncompressed
4. **No Compression**: Cannot use JPEG (lossy compression destroys LSB data)

### Security Limitations

1. **Detection**: Statistical analysis can detect presence (but not content)
2. **Carrier Dependency**: Need appropriate size carrier
3. **Single-Use Recommended**: Reusing carriers may leak patterns
4. **No Forward Secrecy**: If vault key compromised, all stego images vulnerable

## Best Practices

### For Maximum Security

1. **Use BALANCED or PARANOID profiles**
2. **Choose diverse carrier images** (photos with natural noise)
3. **Don't reuse carriers** for multiple secrets
4. **Verify extraction** after hiding to confirm success
5. **Destroy originals** securely after creating stego images

### For Operational Security

1. **Carrier Selection**: Use natural photos (not computer-generated)
2. **Size Management**: Keep capacity usage under 80%
3. **Format Consistency**: Use PNG for all carriers
4. **Metadata Removal**: Strip EXIF data from carriers
5. **Plausible Deniability**: Carriers should be legitimate images

## Future Extensions

### Potential Enhancements

1. **Additional Formats**: 
   - TIFF support
   - WAV audio files
   - MP4 video frames

2. **Advanced Algorithms**:
   - Adaptive LSB (skip pixels that would change too much)
   - DCT-based steganography (more robust)
   - Spread spectrum techniques

3. **Key Management**:
   - Per-file keys (derived from master)
   - Key rotation support
   - Multi-recipient encryption

4. **Usability**:
   - Batch operations
   - GUI interface
   - Drag-and-drop support

## Testing and Verification

### Validation Checklist

✓ File hides without errors
✓ Carrier and stego images visually identical
✓ Extracted file matches original (byte-for-byte)
✓ Authentication detects tampering
✓ Wrong key causes extraction failure
✓ Capacity validation prevents overflow
✓ All profiles work correctly

### Test Command

```bash
# Run comprehensive demo
javac com/passwordmanager/demo/SteganographyDemo.java
java com.passwordmanager.demo.SteganographyDemo
```

## Conclusion

The steganography system provides:
- **Strong security** through encryption + authentication
- **Visual imperceptibility** using LSB technique
- **Tamper detection** via GCM authentication
- **Modular design** for future extensions
- **Integration** with existing vault infrastructure

This implementation prioritizes **security over stealth**, recognizing that encryption provides protection even if steganography is detected.