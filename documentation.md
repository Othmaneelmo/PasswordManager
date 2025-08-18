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
