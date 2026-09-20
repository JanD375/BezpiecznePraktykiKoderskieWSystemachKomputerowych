package projekt;

public class EnvCredentialProvider implements CredentialProvider {
    @Override
    public String getDbUsername() { return System.getenv("DB_USER"); }

    @Override
    public String getDbPassword() { return System.getenv("DB_PASS"); }
}