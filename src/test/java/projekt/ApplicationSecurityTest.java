package projekt;

import org.junit.jupiter.api.Test;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import static org.junit.jupiter.api.Assertions.*;

public class ApplicationSecurityTest {

    @Test
    public void testEncryptedCredentialProvider() throws Exception {
        String masterPass = "TestMasterKey123";
        String encUser = CryptoUtils.encrypt("testUser", masterPass);
        String encPass = CryptoUtils.encrypt("testPass", masterPass);

        CredentialProvider provider = new EncryptedCredentialProvider(encUser, encPass, masterPass);

        assertEquals("testUser", provider.getDbUsername());
        assertEquals("testPass", provider.getDbPassword());
    }

    @Test
    public void testEnvCredentialProvider() {
        CredentialProvider provider = new EnvCredentialProvider();
        assertEquals(System.getenv("DB_USER"), provider.getDbUsername());
    }

    @Test
    public void testRuntimeCredentialProvider() {
        String[] args = {"runtimeUser", "runtimePass"};
        CredentialProvider provider = new RuntimeCredentialProvider(args);

        assertEquals("runtimeUser", provider.getDbUsername());
        assertEquals("runtimePass", provider.getDbPassword());
    }

    @Test
    public void testUserPasswordIsNotStoredInPlainText() throws Exception {
        CredentialProvider stubProvider = new RuntimeCredentialProvider(new String[]{"", ""});
        UserRepository repo = new UserRepository("jdbc:h2:mem:test1;DB_CLOSE_DELAY=-1", stubProvider);

        repo.registerUser("alice", "haslo123");

        try (Connection conn = repo.getConnection();
             PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM app_users WHERE username = 'alice'");
             ResultSet rs = pstmt.executeQuery()) {

            assertTrue(rs.next());
            String dbHash = rs.getString("password_hash");
            assertNotEquals("haslo123", dbHash);
            assertNotNull(rs.getString("salt"));
        }
    }

    @Test
    public void testUserSavedSuccessfullyWithValidHashing() throws Exception {
        CredentialProvider stubProvider = new RuntimeCredentialProvider(new String[]{"", ""});
        UserRepository repo = new UserRepository("jdbc:h2:mem:test2;DB_CLOSE_DELAY=-1", stubProvider);

        String plainPassword = "obo321";
        repo.registerUser("bob", plainPassword);

        try (Connection conn = repo.getConnection();
             PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM app_users WHERE username = 'bob'");
             ResultSet rs = pstmt.executeQuery()) {

            assertTrue(rs.next());
            String storedSalt = rs.getString("salt");
            String storedHash = rs.getString("password_hash");

            String expectedHash = CryptoUtils.hashUserPassword(plainPassword, storedSalt);
            assertEquals(expectedHash, storedHash);
        }
    }
}