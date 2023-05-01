package sirup.service.auth.crypt;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
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

        File file = new File("secret.key");
        if (file.exists()) {
            this.secretKey = loadFromFile(file);
        }
        else {
            this.secretKey = keyGenerator.generateKey();
            saveToFile(file, this.secretKey);
        }


        this.encryptCipher = Cipher.getInstance("AES");
        this.encryptCipher.init(Cipher.ENCRYPT_MODE, this.secretKey);

        this.decryptCipher = Cipher.getInstance("AES");
        this.decryptCipher.init(Cipher.DECRYPT_MODE, this.secretKey);
    }

    private void saveToFile(File file, SecretKey secretKey) {
        System.out.println("Saving key");
        try (FileOutputStream stream = new FileOutputStream(file)) {
            file.createNewFile();
            stream.write(secretKey.getEncoded());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private SecretKey loadFromFile(File file) {
        System.out.println("Loading key");
        byte[] keyBytes;
        try (FileInputStream stream = new FileInputStream(file)) {
            keyBytes = stream.readAllBytes();
        } catch (IOException e) {
            throw new RuntimeException(file.getName() + " not found");
        }
        return new SecretKeySpec(keyBytes, "AES");
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
