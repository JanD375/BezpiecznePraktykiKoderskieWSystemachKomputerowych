package projekt;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class CryptoUtils {

    private static SecretKeySpec getAesKey(String masterPassword) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] key = digest.digest(masterPassword.getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(Arrays.copyOf(key, 16), "AES");
    }

    public static String encrypt(String plainText, String masterPassword) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, getAesKey(masterPassword));
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedText, String masterPassword) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, getAesKey(masterPassword));
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    public static String hashUserPassword(String plainPassword, String salt) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(Base64.getDecoder().decode(salt));
        byte[] hashedPassword = md.digest(plainPassword.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hashedPassword);
    }
}