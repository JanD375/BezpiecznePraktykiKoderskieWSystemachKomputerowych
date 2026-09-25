package projekt;

import java.io.Console;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        Console console = System.console();

        // Config połączenia do bazy danych H2 w pamięci
        String dbUrl = "jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1";
        CredentialProvider provider = new RuntimeCredentialProvider(args);
        UserRepository userRepository = new UserRepository(dbUrl, provider);
        String masterpassward = args[2];

        System.out.println("==========================================");
        System.out.println("  SYSTEM BEZPIECZEŃSTWA UŻYTKOWNIKÓW H2   ");
        System.out.println("==========================================");

        boolean running = true;

        while (running) {
            printMenu();
            System.out.print("Wybierz opcję (1-3): ");
            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1":
                    handleRegistration(scanner, console, userRepository, masterpassward);
                    break;
                case "2":
                    handleLogin(scanner, console, userRepository, masterpassward);
                    break;
                case "3":
                    System.out.println("\nZamykanie aplikacji.");
                    running = false;
                    break;
                default:
                    System.out.println("\n BŁĄD: Nieprawidłowy wybór! Wybierz cyfrę 1, 2 lub 3.");
            }
        }

        scanner.close();
    }

    private static void printMenu() {
        System.out.println("\n---------------- MENU ----------------");
        System.out.println("1. Rejestracja nowego użytkownika");
        System.out.println("2. Logowanie użytkownika");
        System.out.println("3. Wyjście");
        System.out.println("--------------------------------------");
    }

    private static void handleRegistration(Scanner scanner, Console console, UserRepository userRepository, String masterpassward) {
        System.out.println("\n--- REJESTRACJA UŻYTKOWNIKA ---");
        System.out.print("Podaj nazwę użytkownika (login): ");
        String username = scanner.nextLine().trim();

        if (username.isEmpty()) {
            System.out.println(" BŁĄD: Nazwa użytkownika nie może być pusta!");
            return;
        }

        String password = readPasswordInput(console, scanner, "Podaj hasło: ");
        if (password.isEmpty()) {
            System.out.println(" BŁĄD: Hasło nie może być puste!");
            return;
        }

        try {
            String encryptedPassword = CryptoUtils.encrypt(password, masterpassward);
            String encryptedUsername = CryptoUtils.encrypt(username, masterpassward);

            userRepository.registerUser(encryptedUsername, encryptedPassword);
            System.out.println(" SUCCESS: Użytkownik '" + username + "' został pomyślnie zarejestrowany!");
        } catch (Exception e) {
            System.err.println(" BŁĄD: Nie udało się zarejestrować użytkownika.");
            System.err.println("Szczegóły: " + e.getMessage());
        }
    }

    private static void handleLogin(Scanner scanner, Console console, UserRepository userRepository, String masterpassward) {
        System.out.println("\n--- LOGOWANIE UŻYTKOWNIKA ---");
        System.out.print("Podaj nazwę użytkownika (login): ");
        String username = scanner.nextLine().trim();

        String password = readPasswordInput(console, scanner, "Podaj hasło: ");

        try {
            String encryptedPassword = CryptoUtils.encrypt(password, masterpassward);
            String encryptedUsername = CryptoUtils.encrypt(username, masterpassward);

            boolean isAuthenticated = userRepository.authenticateUser(encryptedUsername, encryptedPassword);

            if (isAuthenticated) {
                System.out.println(" SUCCESS: Zalogowano pomyślnie. Witaj, " + username + "!");
            } else {
                System.out.println(" BŁĄD: Niepoprawny login lub hasło.");
            }
        } catch (Exception e) {
            System.err.println(" BŁĄD: Wystąpił problem podczas logowania.");
            System.err.println("Szczegóły: " + e.getMessage());
        }
    }

    private static String readPasswordInput(Console console, Scanner scanner, String prompt) {
        if (console != null) {
            char[] passwordArray = console.readPassword(prompt);
            return new String(passwordArray);
        } else {
            System.out.print(prompt);
            return scanner.nextLine();
        }
    }
}