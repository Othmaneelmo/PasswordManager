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

    //Simple length validation for passoword (>8), NEEDS UPGRADE
    if (masterKeyChars.length < 8) {
      System.out.println("Password too short. Must be at least 8 characters.");
      Arrays.fill(masterKeyChars, ' '); //clear array
    return;
    }

    //Converting Masterkey char[] to byte[] (for MessageDigest API)
    // Convert char[] to byte[] manually (2 bytes per char)
    byte[] masterKeyBytes = new byte[masterKeyChars.length * 2];
    for (int i = 0; i < masterKeyChars.length; i++) {
        masterKeyBytes[i * 2] = (byte) (masterKeyChars[i] >> 8);
        masterKeyBytes[i * 2 + 1] = (byte) masterKeyChars[i];
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
    //to print the hashed MasterKey
    /*if (hashedKey != null) {
      System.out.println(bytesToHex(hashedKey));
    }
    */
  }


//to Print the hashed MasterKey
  /*
  private static String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }
 */
}
