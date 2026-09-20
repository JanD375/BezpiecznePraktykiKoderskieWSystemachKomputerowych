package projekt;

public class RuntimeCredentialProvider implements CredentialProvider {
    private final String user;
    private final String pass;

    public RuntimeCredentialProvider(String[] args) {
        if (args.length < 2) throw new IllegalArgumentException("Missing runtime DB credentials");
        this.user = args[0];
        this.pass = args[1];
    }

    @Override
    public String getDbUsername() { return user; }

    @Override
    public String getDbPassword() { return pass; }
}