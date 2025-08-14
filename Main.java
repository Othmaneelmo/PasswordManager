/*TODO
 * 1. Avoid converting the password to a String — Keep it as a char[] to improve security.
 * 2. Clear the password array after use to avoid it lingering in memory.
 * 3. Add password validation (e.g., length, complexity).
 * 4. Use the master key for something meaningful, like encryption or authentication.
 * 5. Implement functionality to store or verify the master key safely.
 * 6. Handle exceptions and edge cases gracefully.
 * 
 */

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
    /*
    using char array then converting to string because:
        -String are immutable, they are saved in memory
        -can be hacked (memory dump) before java garbage collector removes it
    Using console and not scanner because:
        -Scanner shows password when typed
    */
    char[] masterKeyChars = console.readPassword("Create a Master key: ");


//PASSWORD VALIDATION:
/* this prints out whether the inputted password was valid or not, with a list of reason why not:

 * it takes masterKeyChars (char[]) as a parameter, 
 * PasswordValidator.validate() method checks for password complexity, and add reason X if rule Y is not respected
 * PasswordValidator.validate() method returns ValidationResult(reasons.isEmpty(), reasons)
 * the latter ValidationResult() returns whether the passowrd is valid (boolean ok), and the reasons (List<String> messages)
 * from the above return statements, this code section below prints appropriate messages(according to the return stats), AND CLEARS THE INVALID PASSWORD (char[])
*/
    ValidationResult vr = PasswordValidator.validate(masterKeyChars);
    if (!vr.ok()) {
      System.out.println("Password not strong enough:");
      for (String msg : vr.messages()) System.out.println(" - " + msg);
      Arrays.fill(masterKeyChars, ' '); // clear array before exiting
      return;
    }

    //Converting Masterkey char[] to byte[] (for MessageDigest API)
    // Convert char[] to byte[] manually (2 bytes per char) (UTF-16 encoding)
    byte[] masterKeyBytes = new byte[masterKeyChars.length * 2];
    for (int i = 0; i < masterKeyChars.length; i++) {
        masterKeyBytes[i * 2] = (byte) (masterKeyChars[i] >> 8); //high byte
        masterKeyBytes[i * 2 + 1] = (byte) masterKeyChars[i]; //low byte
    }
    // Clear char[] asap
    Arrays.fill(masterKeyChars, ' ');

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
    
  }
}
