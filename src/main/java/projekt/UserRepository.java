package projekt;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;

public class UserRepository {
    private static final String DB_URL = "jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1";
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
        String urlWithDelay = jdbcUrl.contains(";DB_CLOSE_DELAY=-1") ? jdbcUrl : jdbcUrl + ";DB_CLOSE_DELAY=-1";
        return DriverManager.getConnection(jdbcUrl, provider.getDbUsername(), provider.getDbPassword());
    }

    public void registerUser(String username, String plainPassword) throws Exception {
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
}