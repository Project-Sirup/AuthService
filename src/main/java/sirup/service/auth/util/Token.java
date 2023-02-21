package sirup.service.auth.util;

import sirup.service.auth.crypt.CryptB64;
import sirup.service.auth.crypt.ICrypt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;

public class Token {
    private final String value;
    private final Date createdDate;
    private final Date expireDate;
    private final Credentials credentials;
    private static ICrypt crypt = new CryptB64();

    /**
     * Default Token with a duration of 1 day
     */
    public Token(final Credentials credentials) {
        this.createdDate = new Date();
        this.expireDate = new Date(this.createdDate.getTime() + Duration.DurationUnit.DAY.unit);
        this.value = genValue(credentials);
        this.credentials = credentials;
    }

    /**
     * Token with a specific valid duration
     * @param duration token's valid duration
     */
    public Token(final Credentials credentials, final Duration duration) {
        this.createdDate = new Date();
        this.expireDate = new Date(this.createdDate.getTime() + (duration.duration() * duration.durationUnit().unit));
        this.value = genValue(credentials);
        this.credentials = credentials;
    }

    /**
     * Used for creating a Token from string
     * @param value the provided value in the string
     * @param createdDate the provided creation date
     * @param expireDate the provided expiration date
     */
    private Token(final String value, final Date createdDate, final Date expireDate, final Credentials credentials) {
        this.value = value;
        this.createdDate = createdDate;
        this.expireDate = expireDate;
        this.credentials = credentials;
    }

    /**
     * Set another {@link ICrypt} implementation
     * @param crypt the new encryption algorithm used for tokens
     */
    public static void setCrypt(ICrypt crypt) {
        Token.crypt = crypt;
    }

    /**
     * Creates a Token from a string
     * @param tokenString the string version of a Token
     * @return new Token
     */
    public static Token fromTokenString(String tokenString) {
        if (tokenString.equals("")) {
            throw new IllegalArgumentException("tokenString must not be empty!");
        }
        String decodedTokenString = crypt.decode(tokenString);
        String[] strings = decodedTokenString.split(":");
        Credentials credentials = new Credentials(strings[0],strings[1],strings[2]);
        Date created = new Date(Long.parseLong(strings[strings.length - 3]));
        Date expire = new Date(Long.parseLong(strings[strings.length - 2]));
        return new Token(tokenString,created,expire,credentials);
    }

    /**
     * The encoded token string
     * @return a string version of the Token
     */
    public String toTokenString() {
        return this.value;
    }

    private String genValue(Credentials credentials) {
        String plainText =  credentials.username() + ":" +
                            credentials.password() + ":" +
                            credentials.privilege() + ":" +
                            this.createdDate.getTime() + ":" +
                            this.expireDate.getTime() + ":" +
                            Env.PRIVATE_KEY;
        return crypt.encode(plainText);
    }

    /**
     * Check if the given token is still valid
     * @return true if the token is valid, otherwise false
     */
    public boolean isValid() {
        String[] split = crypt.decode(this.value).split(":");
        String key = split[split.length - 1];
        return this.createdDate.before(this.expireDate) && key.equals(Env.PRIVATE_KEY);
    }

    /**
     * Get the credential provided when the Token was created
     * @return the privilege of the credentials
     */
    public String getPrivilege() {
        return this.credentials.privilege();
    }

    /**
     * @deprecated use {@link ICrypt#decode(String)} implementation
     */
    private static String decode(String encodedString) {
        return new String(Base64.getDecoder().decode(encodedString));
    }

    /**
     * @deprecated use {@link ICrypt#encode(String)} implementation
     */
    private String encode(String plainText) {
        return Base64.getEncoder().encodeToString(plainText.getBytes(StandardCharsets.UTF_8));
    }
}
