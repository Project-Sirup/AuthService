package sirup.service.auth.util;

import sirup.service.auth.crypt.ICrypt;

public class Authenticator {

    private final Policy policy;

    /**
     *
     * @param policy the policy for tokens
     * @param crypt the encryption algorithm used for tokens
     */
    public Authenticator(final Policy policy, final ICrypt crypt) {
        this.policy = policy;
        Token.setCrypt(crypt);
    }

    public boolean auth(Token token) {
        return token.isValid();
    }

    public boolean auth(String tokenString) {
        return auth(Token.fromTokenString(tokenString));
    }

    public Token getToken(Credentials credentials) {
        switch (policy) {
            case SHORT -> {
                return new Token(credentials, Duration.SHORT);
            }
            case MEDIUM -> {
                return new Token(credentials, Duration.MEDIUM);
            }
            case LONG -> {
                return new Token(credentials, Duration.LONG);
            }
            case VERY_LONG -> {
                return new Token(credentials, Duration.VERY_LONG);
            }
            default -> {
                return new Token(credentials);
            }
        }
    }

    public enum Policy {
        DEFAULT,
        SHORT,
        MEDIUM,
        LONG,
        VERY_LONG;
    }
}
