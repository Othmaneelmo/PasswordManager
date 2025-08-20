## TODO
    below paragraphs should be removed/documented
    Need to document PasswordValidator / ValidationResult
    Need to add a table of content


# Introduction:
This project is to build a secure password manager in Java. The main goal is not only to write working code but to understand the security reasoning behind every design choice. 

Password managers are security-critical software: they protect sensitive information like master keys, stored account credentials, and even files. A single weak spot (such as using String to hold a password, or using a fast hash like plain SHA-256) can expose the entire vault to attackers.

That’s why this documentation is more than just code comments — it serves three purposes:

**1. Code Walkthrough :**
Each commit and code snippet is explained with why it exists and what security problem it solves. This way, a beginner can follow the development process step by step.

**2. Design Notes :**
Important security trade-offs (e.g., char[] vs String, PBKDF2 vs SHA-256) are recorded so that future maintainers — or learners reading this later — understand the reasoning behind the decisions.

**3. Reference Guide :** 
As the project grows, this document becomes a source of truth for how passwords are processed, hashed, and stored, as well as how the vault’s encryption and command-line interface (CLI) work. This improves maintainability and helps avoid repeating mistakes.

---

### Project Setup
Let us start with setting up the project.
We create the main class and method. Always start from a working baseline, even if it just prints something.
```java
public class Main {
  public static void main(String[] args) {
    System.out.println("Password Manager starting...");
  }
}
````


---

### Detect system console

```java
import java.io.Console;

public class Main {
  public static void main(String[] args) {
    Console console = System.console();

    if (console == null) {
      System.out.println("console not working, use a terminal!");
      return;
    }

    System.out.println("Console is available.");
  }
}
```
This adds console detection with fallback

**Explanation:**

* Java’s `System.console()` allows secure password entry.
* If run inside an IDE (like IntelliJ or VSCode), `console` might be `null`.
* We handle this gracefully by showing a message and exiting.

---

### Capture password as char\[]

```java
import java.io.Console;

public class Main {
  public static void main(String[] args) {
    Console console = System.console();

    if (console == null) {
      System.out.println("console not working, use a terminal!");
      return;
    }

    char[] masterKeyChars = console.readPassword("Create a Master key: ");
    System.out.println("Password captured (hidden while typing).");
  }
}
```

This securely capture password input as char[]

**Explanation:**

* `readPassword()` hides typed characters (unlike `Scanner`).
* Passwords are stored as `char[]` instead of `String` so we can erase them from memory later.
* At this stage, we just confirm capture (without printing it).

---

### Temporary String conversion for demo

```java
import java.io.Console;

public class Main {
  public static void main(String[] args) {
    Console console = System.console();

    if (console == null) {
      System.out.println("console not working, use a terminal!");
      return;
    }

    char[] masterKeyChars = console.readPassword("Create a Master key: ");
    String masterKey =
        new String(masterKeyChars); // insecure, demo only

    System.out.println("Your master key is : " + masterKey);
  }
}
```
This prints password by converting char[] to String (demo only)

**Explanation:**

* For testing, we convert the `char[]` into a `String` and print it.
* This is **insecure**: `String` is immutable and can linger in memory.
* This step is purely for **demonstration and debugging** — later commits will remove it.

---

### Add inline documentation

```java
import java.io.Console;

public class Main {
  public static void main(String[] args) {
    Console console = System.console();

    if (console == null) {
      System.out.println("console not working, use a terminal!");
      return;
    }

    /*
     Why char[] instead of String?
       - String is immutable, it stays in memory until garbage collection.
       - If memory is dumped, an attacker may retrieve it.
     Why Console and not Scanner?
       - Scanner shows characters while typing, not safe for passwords.
    */
    char[] masterKeyChars = console.readPassword("Create a Master key: ");
    String masterKey =
        new String(masterKeyChars); // demo only — will be replaced later

    System.out.println("Your master key is : " + masterKey);
  }
}
```

We document design decisions (char[] vs String, Console vs Scanner)`

**Explanation:**

* Comments clarify security trade-offs.
* This helps future readers understand *why* we do things a certain way.

---


## Next Steps

### 1- Password Validation

```java
    char[] masterKeyChars = console.readPassword("Create a Master key: ");
    //Simple length validation for password (>8), NEEDS UPGRADE
    if (masterKeyChars.length < 8) {
      System.out.println("Password too short. Must be at least 8 characters.");
      Arrays.fill(masterKeyChars, ' '); //clear array
    return;
    }
```

Just as a start, we won't let users enter master keys with less than 8 characters. If they do, the array containing the master key is cleared.

---

### 2- Converting the char\[] into byte\[] then hash

```java
//Converting Masterkey char[] to byte[] (for MessageDigest API)
/*we still convert Master key to String, we need to figure out a way to do it more safely */
byte[] masterKeyBytes = new String(masterKeyChars).getBytes();
Arrays.fill(masterKeyChars, ' ');

MessageDigest digest = MessageDigest.getInstance("SHA-256");
byte[] hashedKey = digest.digest(masterKeyBytes);
Arrays.fill(masterKeyBytes, (byte) 0);
```

However, there is a problem: by converting it from `char[]` to `byte[]`, we first turn the master key into a `String`, which can be hacked (memory dump). We need a safer way to do so:

```java
//Converting Masterkey char[] to byte[] (for MessageDigest API)
// Convert char[] to byte[] manually (2 bytes per char)
byte[] masterKeyBytes = new byte[masterKeyChars.length * 2];
for (int i = 0; i < masterKeyChars.length; i++) {
    masterKeyBytes[i * 2] = (byte) (masterKeyChars[i] >> 8); //high byte
    masterKeyBytes[i * 2 + 1] = (byte) masterKeyChars[i]; //low byte
}
// Clear char[] asap
Arrays.fill(masterKeyChars, ' ');
```

Java `char` is 16 bits long (2 bytes), because it supports UTF-16 encoding. Therefore the newly made `byte[]` array is double the size of the `char[]` array:

Example:
Initial char\[]:

```java
char[] masterKeyChars = { 'A', 'B', 'C' };
```

* `'A'` = Unicode U+0041 → 16-bit: `0000 0000 0100 0001` (hex: `0x00 0x41`)
* `'B'` = Unicode U+0042 → 16-bit: `0000 0000 0100 0010` (hex: `0x00 0x42`)
* `'C'` = Unicode U+0043 → 16-bit: `0000 0000 0100 0011` (hex: `0x00 0x43`)

```java
byte[] masterKeyBytes = new byte[masterKeyChars.length * 2];
```

The size is `3 * 2 = 6` bytes.

Loop conversion:

```java
for (int i = 0; i < masterKeyChars.length; i++) {
    masterKeyBytes[i * 2] = (byte) (masterKeyChars[i] >> 8);
    masterKeyBytes[i * 2 + 1] = (byte) masterKeyChars[i];
}
```

* `i = 0 ('A'):`

  * `masterKeyChars[0] >> 8 = 0x0000 → (byte) 0x00 → 0`
  * `(byte) masterKeyChars[0] = (byte) 0x0041 → 65`
  * Stored as: `masterKeyBytes[0] = 0`, `masterKeyBytes[1] = 65`

`(masterKeyChars[i] >> 8)` shifts the character in the `char[]` by 8 bits to the right, allowing us to select the high byte.

**Final byte\[] values:**

* Decimal form: `[0, 65, 0, 66, 0, 67]`
* Hex form: `[0x00, 0x41, 0x00, 0x42, 0x00, 0x43]`

---

While if UTF-8 encoding had been used, the output would have been:

* Decimal form: `[65, 66, 67]`
* Hex form: `[0x41, 0x42, 0x43]`

### 3- Exception Handling for MessageDigest.getInstance()

Trying to run the code at this stage causes the following compilation error:  
**`NoSuchAlgorithmException`** — this is thrown when a particular cryptographic algorithm is requested but not available in the environment.

To fix this, `MessageDigest.getInstance()` must be placed inside a **try-catch block**:

```java
byte[] hashedKey = null; // declare outside try
try {
  MessageDigest digest = MessageDigest.getInstance("SHA-256");
  hashedKey = digest.digest(masterKeyBytes);
  Arrays.fill(masterKeyBytes, (byte) 0);

} catch (NoSuchAlgorithmException e) {
  System.out.println("SHA-256 algorithm not available. Exiting...");
  Arrays.fill(masterKeyChars, ' ');  // Clear password on error too
  return;
}
````


For testing purposes, this section allows us to see the hashed master key as output:

```java
// to print the hashed MasterKey
if (hashedKey != null) {
  System.out.println(bytesToHex(hashedKey));
}

// Helper method
private static String bytesToHex(byte[] bytes) {
  StringBuilder sb = new StringBuilder();
  for (byte b : bytes) {
    sb.append(String.format("%02x", b));
  }
  return sb.toString();
}
```
At this point, our Main.java code should look  like the following:
```java
import java.io.Console;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Main {
  public static void main(String[] args) {

    Console console = System.console();
    if (console == null) {
      System.out.println("console not working, use a terminal!");
      return;
    }
    char[] masterKeyChars = console.readPassword("Create a Master key: ");

    ValidationResult vr = PasswordValidator.validate(masterKeyChars);
    if (!vr.ok()) {
      System.out.println("Password not strong enough:");
      for (String msg : vr.messages()){
        System.out.println(" - " + msg);
      }
      Arrays.fill(masterKeyChars, ' '); // clear array before exiting
      return;
    }

    byte[] masterKeyBytes = new byte[masterKeyChars.length * 2];
    for (int i = 0; i < masterKeyChars.length; i++) {
        masterKeyBytes[i * 2] = (byte) (masterKeyChars[i] >> 8); //high byte
        masterKeyBytes[i * 2 + 1] = (byte) masterKeyChars[i]; //low byte
    }
    Arrays.fill(masterKeyChars, ' ');    // Clear char[] asap

    byte[] hashedKey = null; 
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      hashedKey = digest.digest(masterKeyBytes);
      Arrays.fill(masterKeyBytes, (byte) 0);    
    } catch (NoSuchAlgorithmException e) {
      System.out.println("SHA-256 algorithm not available. Exiting...");
      Arrays.fill(masterKeyChars, ' ');  // Clear password on error too
      return;
    }
    
  }
}

```
Right before the try block, we already did clear the char[], yet we still clear it in the catch block
```java
Arrays.fill(masterKeyChars, ' ');  // Clear password on error too
````
That means by the time execution reaches the catch, masterKeyChars is already wiped, so it’s redundant, BUT not harmful.
I will keep it either way, since it shows that we always clear char[] when were done using it.
### CHANGING THE ENCRYPTION

After further research, I realized that this encryption method is not secure for real-life password storage. A plain SHA-256 hash is too fast for password/key storage. Attackers can brute-force billions of guesses per second. 

Therefore, the answer is adding a **salt** and using **slow hashing**:  
We have 2 options: using **PBKDF2** (Java library) or **Argon2** (other options exist).  

Example of cost estimates for an 8-character password with uppercase, lowercase, and digits:
[According to 1Password's analysis](https://blog.1password.com/cracking-challenge-update/)

* PBKDF2 100,000 iterations - \$38,000  
* PBKDF2 600,000 iterations - \$228,000  
* Argon2 Bitwarden defaults - \$16.2 million  
* Argon2 (t=10, m=512MB, p=4) - \$486.5 million  

Observation: Both options are costly for hackers to brute-force, with Argon2 being much more expensive. However, since this is a learning project, **PBKDF2 is sufficient** and convenient (official Java library). Argon2 can be implemented later if the project scales.

---
now the TODO list changes to the following:
### TODO

1. **Replace plain SHA-256 with PBKDF2WithHmacSHA256**
   * Use `javax.crypto.SecretKeyFactory` with `"PBKDF2WithHmacSHA256"`.
   * Use a random salt (16–32 bytes) for each password.
   * Use a high iteration count (~600,000) for better security.
   * Store: hash + salt + iteration count.
   * Use `SecureRandom` for generating salts.

2. **Implement password verification**
   * On login, load salt + iteration count + hash from storage.
   * Run PBKDF2 with the same parameters on the entered password.
   * Compare results securely (constant-time).
   * Keep derived encryption key only in memory after unlock.

3. **Update storage format**
   * Save hash, salt, iteration count per master key.
   * Store encrypted account passwords (AES-GCM recommended) with IVs.
   * Consider a `formatVersion`/`algorithmVersion` field for future upgrades.

4. **Add CLI menu (top-level interface)**


```
   [1] Set/Reset Master Key       # Create or change the vault's master key
   [2] Unlock Vault               # Authenticate to access stored passwords
   [3] Add Account Password       # Store account name + password (encrypted)
   [4] List Accounts              # Show saved account names (but not passwords)
   [5] Retrieve Account Password  # Decrypt & show password for chosen account
   [6] Encrypt a File             # Bonus: encrypt file with derived key
   [7] Decrypt a File             # Bonus: decrypt file with derived key
   [0] Exit
```



5. **Project structure / utilities**
* Keep crypto logic in separate classes (`PasswordHasher`, `VaultStorage`, `CryptoUtils`).
* Plan storage location (file, JSON, or SQLite) for hashes + encrypted data.
* Ensure secure random generation for salts, IVs, etc.

6. **Testing**
* Verify password hashing and verification.
* Verify encryption/decryption of account passwords and files.
* Test edge cases (empty/long passwords, invalid input).
* Ensure login/unlock is reasonably fast (< 1 second).

7. **Logging / safety**
* Do not log sensitive data (plaintext passwords, keys, hashes).
* Use logging only for general program flow/debug info.

**Note:** PBKDF2 is secure enough for this learning project. No need to add Argon2 or other KDFs.



### 1- Replace plain SHA-256 with PBKDF2withHmacSHA256
Before we move on to the code, we must understand why we're doing this; how does SHA-256 work, and why is it not secure, and how does PBKDF2WithHmacSHA256 work, and why is it secure. But to leave this file concrete and code progression focused, this will be discussed in the file [SHA-256 to PBKDF2PBKDF2withHmacSHA256 explanation](/documentation/SHA-256%20to%20PBKDF2WithHmacSHA256.md)


We no longer use SHA-256 via `MessageDigest`, so we remove the following imports:

```java
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
````

And we remove the previous SHA-256 block:

```java
byte[] hashedKey = null; // declare outside try, (not used but could be for testing purposes or future uses)
try {
  MessageDigest digest = MessageDigest.getInstance("SHA-256");
  hashedKey = digest.digest(masterKeyBytes);
  Arrays.fill(masterKeyBytes, (byte) 0);    
} catch (NoSuchAlgorithmException e) {
  System.out.println("SHA-256 algorithm not available. Exiting...");
  Arrays.fill(masterKeyChars, ' ');  // Clear password on error too
  return;
}
```

We also remove the manual char\[] → byte\[] conversion, since PBKDF2 works directly with `char[]`:

```java
// Convert char[] to byte[] manually (2 bytes per char) (UTF-16 encoding)
byte[] masterKeyBytes = new byte[masterKeyChars.length * 2];
for (int i = 0; i < masterKeyChars.length; i++) {
    masterKeyBytes[i * 2] = (byte) (masterKeyChars[i] >> 8); //high byte
    masterKeyBytes[i * 2 + 1] = (byte) masterKeyChars[i]; //low byte
}
Arrays.fill(masterKeyChars, ' ');    // Clear char[] asap
```

Now we are ready to add **PBKDF2withHmacSHA256**.
Lets first add PBKDF2-related imports 
```java
+ import java.security.SecureRandom;
+ import java.util.Base64;
+ import javax.crypto.SecretKeyFactory;
+ import javax.crypto.spec.PBEKeySpec;
```

Next we add the Salt generation:
We need a random salt to make sure the same password doesn’t always produce the same hash.

Add the following:
```java
SecureRandom saltGenerator = new SecureRandom();
byte[] salt = new byte[16]; // 16 bytes = 128 bits
saltGenerator.nextBytes(salt);
```

* SecureRandom is a cryptographically secure random number generator.

* salt is a 16-byte random value (128 bits is enough for salts).

* nextBytes fills the salt array with secure random values.

Next we encode the salt to be able to store it, we use Base64 encoding:

Salts are binary data, so we need to store them in a readable format:
```java
String encodedSalt = Base64.getEncoder().encodeToString(salt);
```

Base64 turns the raw bytes into a printable string.

This makes it easier to save the salt in files, databases, or text-based formats.




