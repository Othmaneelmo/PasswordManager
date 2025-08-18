# Hello

## Improvements / Recommendations
1. Avoid converting the password to a `String` — keep it as a `char[]` to improve security.
2. Clear the password array after use to avoid it lingering in memory.
3. Add password validation (e.g., length, complexity).
4. Use the master key for something meaningful, like encryption or authentication.
5. Implement functionality to store or verify the master key safely.
6. Handle exceptions and edge cases gracefully.

---

## Example Code

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
     Using char array then converting to string because:
       - String is immutable, it remains in memory
       - Can be hacked (memory dump) before Java garbage collector removes it
     Using console and not scanner because:
       - Scanner shows password when typed
    */
    char[] masterKeyChars = console.readPassword("Create a Master key: ");
    String masterKey =
        new String(masterKeyChars); // replace later (it also makes a String out
                                    // of the password)

    System.out.println("Your master key is : " + masterKey);
  }
}
````

---

## Program Description

This Java program securely reads a master key from the user by leveraging the `Console` class’s `readPassword()` method, which prevents password characters from being echoed on the screen during input — unlike `Scanner`, which shows typed characters and is less secure for passwords.

The password is initially read as a `char[]` array to allow explicit clearing from memory, since `String` objects in Java are immutable and can linger in memory, posing a security risk if exposed through memory dumps.

Although the code temporarily converts the `char[]` to a `String` for ease of use and demonstration, this is flagged as a **security trade-off** to be addressed later, as storing passwords in immutable `String` form should be avoided.

The program also checks that a console is available before proceeding, since `System.console()` returns `null` in environments without a proper terminal, ensuring graceful failure.

Finally, for testing purposes, it prints the entered master key — which in a production environment should be removed to maintain password confidentiality.

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

