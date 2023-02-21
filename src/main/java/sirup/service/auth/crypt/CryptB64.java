package sirup.service.auth.crypt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class CryptB64 implements ICrypt {
    @Override
    public String encode(String plainText) {
        return Base64.getEncoder().encodeToString(plainText.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public String decode(String encryptedText) {
        return new String(Base64.getDecoder().decode(encryptedText));
    }
}
