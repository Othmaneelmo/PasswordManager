import java.io.Console;

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
    char[] passwordsChars = console.readPassword("Create a Master key: ");
    String masterKey =
        new String(passwordsChars); // replace later (it also makes a String out
                                    // of the password)

    System.out.println("Your master key is : " + masterKey);
  }
}
