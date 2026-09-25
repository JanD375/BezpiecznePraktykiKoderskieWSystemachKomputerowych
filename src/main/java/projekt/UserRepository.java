package projekt;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.sql.ResultSet;


public class UserRepository {
    private final String jdbcUrl;
    private final CredentialProvider provider;

    public UserRepository(String jdbcUrl, CredentialProvider provider) {
        this.jdbcUrl = jdbcUrl;
        this.provider = provider;
        initDatabase();
    }

    private void initDatabase() {
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS app_users (" +
                    "id INT AUTO_INCREMENT PRIMARY KEY, " +
                    "username VARCHAR(50) UNIQUE, " +
                    "salt VARCHAR(100), " +
                    "password_hash VARCHAR(100))");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public Connection getConnection() throws Exception {
        return DriverManager.getConnection(jdbcUrl, provider.getDbUsername(), provider.getDbPassword());
    }

    public void registerUser(String encryptedUsername, String encryptedPassword) throws Exception {
        CredentialProvider provider = new EncryptedCredentialProvider(encryptedUsername, encryptedPassword,"szyfrowanie");
        String plainPassword = provider.getDbPassword();
        String username = provider.getDbUsername();
        String salt = CryptoUtils.generateSalt();
        String hash = CryptoUtils.hashUserPassword(plainPassword, salt);

        String sql = "INSERT INTO app_users (username, salt, password_hash) VALUES (?, ?, ?)";
        try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            pstmt.setString(2, salt);
            pstmt.setString(3, hash);
            pstmt.executeUpdate();
            System.out.println("User " + username + " registered securely!");
        }
    }

    public boolean authenticateUser(String encryptedUsername, String encryptedPassword) throws Exception {
        String sql = "SELECT salt, password_hash FROM app_users WHERE username = ?";
        CredentialProvider provider = new EncryptedCredentialProvider(encryptedUsername, encryptedPassword,"szyfrowanie");
        String password = provider.getDbPassword();
        String username = provider.getDbUsername();

        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, username);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    String salt = rs.getString("salt");
                    String storedHash = rs.getString("password_hash");
                    String computedHash = CryptoUtils.hashUserPassword(password, salt);
                    return storedHash.equals(computedHash);
                }
            }
        } catch (Exception e) {
            System.err.println("Błąd bazy danych podczas logowania: " + e.getMessage());
        }
        return false;
    }
}