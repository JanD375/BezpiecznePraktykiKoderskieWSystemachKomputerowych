package projekt;

public class EncryptedCredentialProvider implements CredentialProvider {
    private final String encryptedUser;
    private final String encryptedPass;
    private final String masterPassword;

    public EncryptedCredentialProvider(String encryptedUser, String encryptedPass, String masterPassword) {
        this.encryptedUser = encryptedUser;
        this.encryptedPass = encryptedPass;
        this.masterPassword = masterPassword;
    }

    @Override
    public String getDbUsername() {
        try { return CryptoUtils.decrypt(encryptedUser, masterPassword); }
        catch (Exception e) { throw new RuntimeException("Decryption failed", e); }
    }

    @Override
    public String getDbPassword() {
        try { return CryptoUtils.decrypt(encryptedPass, masterPassword); }
        catch (Exception e) { throw new RuntimeException("Decryption failed", e); }
    }
}