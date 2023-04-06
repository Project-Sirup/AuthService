package sirup.service.auth.crypt;

import javax.crypto.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class CryptAES implements ICrypt {

    private final SecretKey secretKey;

    private final Cipher encryptCipher;
    private final Cipher decryptCipher;

    public CryptAES() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        this.secretKey = keyGenerator.generateKey();

        this.encryptCipher = Cipher.getInstance("AES");
        this.encryptCipher.init(Cipher.ENCRYPT_MODE, this.secretKey);

        this.decryptCipher = Cipher.getInstance("AES");
        this.decryptCipher.init(Cipher.DECRYPT_MODE, this.secretKey);
    }

    @Override
    public String encode(String plainText) {
        String encodeText;
        try {
            encodeText = Base64.getEncoder().encodeToString(this.encryptCipher.doFinal(plainText.getBytes()));
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            encodeText = "ERROR";
            e.printStackTrace();
        }
        return encodeText;
    }

    @Override
    public String decode(String encryptedText) throws IllegalBlockSizeException, BadPaddingException {
        return new String(this.decryptCipher.doFinal(Base64.getDecoder().decode(encryptedText.getBytes(StandardCharsets.UTF_8))));
    }
}
