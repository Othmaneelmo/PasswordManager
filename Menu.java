/*this file might become the main entry point (with PSVM method), so 
 * OR
 * just add all of this in main.java
 * 
 * wont decide yet until further refactoring. this file is just a reminder of a proper cli menu (for now)
 */
//TODO: refactor Main.java



import java.util.Scanner;

public class Menu {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        int choice = -1;

        while (choice != 0) {
            // Print menu
            System.out.println("\n=== Vault Menu ===");
            System.out.println("[1] Set/Reset Master Key");
            System.out.println("[2] Unlock Vault");
            System.out.println("[3] Add Account Password");
            System.out.println("[4] List Accounts");
            System.out.println("[5] Retrieve Account Password");
            System.out.println("[6] Encrypt a File");
            System.out.println("[7] Decrypt a File");
            System.out.println("[0] Exit");
            System.out.print("Choose an option: ");

            // Read input safely
            if (scanner.hasNextInt()) {
                choice = scanner.nextInt();
                scanner.nextLine(); // clear newline
            } else {
                System.out.println("Invalid input. Please enter a number.");
                scanner.nextLine(); // discard invalid input
                continue;
            }

            // Handle choice
            switch (choice) {
                case 1 -> System.out.println("You chose [1] Set/Reset Master Key");
                case 2 -> System.out.println("You chose [2] Unlock Vault");
                case 3 -> System.out.println("You chose [3] Add Account Password");
                case 4 -> System.out.println("You chose [4] List Accounts");
                case 5 -> System.out.println("You chose [5] Retrieve Account Password");
                case 6 -> System.out.println("You chose [6] Encrypt a File");
                case 7 -> System.out.println("You chose [7] Decrypt a File");
                case 0 -> System.out.println("Exiting... Goodbye!");
                default -> System.out.println("Invalid choice. Please try again.");
            }
        }

        scanner.close();
    }
}
