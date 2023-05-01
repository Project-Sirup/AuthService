package sirup.service.auth.util;

import sirup.service.auth.crypt.CryptB64;
import sirup.service.auth.crypt.ICrypt;
import sirup.service.log.rpc.client.LogClient;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

public class Token {
    private final String value;
    private final Date expireDate;
    private final Credentials credentials;
    private static ICrypt crypt = new CryptB64();

    private static final LogClient logger = LogClient.getInstance();

    /**
     * Default Token with a duration of 1 day
     */
    public Token(final Credentials credentials) {
        this.expireDate = new Date(System.currentTimeMillis() + Duration.DurationUnit.DAY.unit);
        this.value = genValue(credentials);
        this.credentials = credentials;
    }

    /**
     * Token with a specific valid duration
     * @param duration token's valid duration
     */
    public Token(final Credentials credentials, final Duration duration) {
        if (duration.durationUnit().equals(Duration.DurationUnit.MAX)) {
            this.expireDate = new Date(Long.MAX_VALUE);
        }
        else {
            this.expireDate = new Date(System.currentTimeMillis() + (duration.duration() * duration.durationUnit().unit));
        }
        this.value = genValue(credentials);
        this.credentials = credentials;
    }

    /**
     * Used for creating a Token from string
     * @param value the provided value in the string
     * @param expireDate the provided expiration date
     */
    private Token(final String value, final Date expireDate, final Credentials credentials) {
        this.value = value;
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
    public static Optional<Token> fromTokenString(String tokenString) {
        if (tokenString.equals("")) {
            throw new IllegalArgumentException("tokenString must not be empty!");
        }
        try {
            String decodedTokenString = crypt.decode(tokenString);
            String[] strings = decodedTokenString.split(":");
            Credentials credentials = new Credentials(strings[0], Integer.parseInt(strings[1]));
            Date expire = new Date(Long.parseLong(strings[strings.length - 2]));
            return Optional.of(new Token(tokenString,expire,credentials));
        } catch (IllegalBlockSizeException | BadPaddingException | NumberFormatException e) {
            logger.warn(e.getMessage());
        }
        return Optional.empty();
    }

    /**
     * The encoded token string
     * @return a string version of the Token
     */
    public String toTokenString() {
        return this.value;
    }

    private String genValue(Credentials credentials) {
        String plainText =  credentials.userID() + ":" +
                            credentials.systemAccess() + ":" +
                            this.expireDate.getTime() + ":" +
                            Env.PRIVATE_KEY;
        return crypt.encode(plainText);
    }

    /**
     * Check if the given token is still valid
     * @return true if the token is valid, otherwise false
     */
    public boolean isValid(Credentials credentials) {
        try {
            String[] split = crypt.decode(this.value).split(":");
            String key = split[split.length - 1];
            return System.currentTimeMillis() < this.expireDate.getTime() &&
                    key.equals(Env.PRIVATE_KEY) &&
                    this.credentials.userID().equals(credentials.userID()) &&
                    this.credentials.systemAccess() == credentials.systemAccess();
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return false;
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
