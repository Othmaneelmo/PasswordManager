package com.passwordmanager.stego;
/**
 * High-level steganography engine that composes encryption and embedding.
 * <p>
 * <b>Hide Operation:</b>
 * </p>
 * <pre>
 * 1. Read secret file
 * 2. Encrypt with vault session key (AES-GCM)
 * 3. Create header (magic, profile, size, filename)
 * 4. Combine: [Header][Encrypted Payload]
 * 5. Embed into carrier image (LSB)
 * 6. Save modified carrier
 * </pre>
 * 
 * <p><b>Extract Operation:</b>
 * </p>
 * <pre>
 * 1. Load carrier image
 * 2. Extract header (parse metadata)
 * 3. Extract encrypted payload
 * 4. Decrypt with vault session key
 * 5. Verify authentication (AES-GCM tag)
 * 6. Save recovered file
 * </pre>
 * 
 * <p><b>Security Guarantees:</b></p>
 * <ul>
 *   <li>Plaintext never touches disk</li>
 *   <li>All embedded data is encrypted</li>
 *   <li>Authentication tag prevents tampering</li>
 *   <li>No keys embedded in carrier</li>
 *   <li>Failed authentication = no output</li>
 * </ul>
 */
public class StegoEngine {
    
}
