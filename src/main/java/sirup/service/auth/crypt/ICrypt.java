package sirup.service.auth.crypt;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public interface ICrypt {
    String encode(String plainText);
    String decode(String encryptedText) throws IllegalBlockSizeException, BadPaddingException;
}
