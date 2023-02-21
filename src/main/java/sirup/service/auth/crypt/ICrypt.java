package sirup.service.auth.crypt;

public interface ICrypt {
    String encode(String plainText);
    String decode(String encryptedText);
}
