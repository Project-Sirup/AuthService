package sirup.service.auth.crypt;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class CryptRSA implements ICrypt {

    private final Cipher encryptCipher;
    private final Cipher decryptCipher;

    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    public CryptRSA() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        this.publicKey = pair.getPublic();
        this.privateKey = pair.getPrivate();

        this.encryptCipher = Cipher.getInstance("RSA");
        this.encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        this.decryptCipher = Cipher.getInstance("RSA");
        this.decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
    }

    @Override
    public String encode(String plainText) {
        String encodedText;
        try {
            encodedText = Base64.getEncoder().encodeToString(this.encryptCipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8)));
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            encodedText = "ERROR";
            e.printStackTrace();
        }
        return encodedText;
    }

    @Override
    public String decode(String encryptedText) throws IllegalBlockSizeException, BadPaddingException {
        return new String(this.decryptCipher.doFinal(Base64.getDecoder().decode(encryptedText.getBytes(StandardCharsets.UTF_8))));
    }
}
