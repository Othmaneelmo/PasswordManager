
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

1- Password Validation

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

