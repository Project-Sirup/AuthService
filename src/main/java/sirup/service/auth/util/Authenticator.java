package sirup.service.auth.util;

import sirup.service.auth.crypt.ICrypt;

import java.util.Optional;

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

    public boolean auth(Token token, Credentials credentials) {
        System.out.println(token.toTokenString());
        return token.isValid(credentials);
    }

    public boolean auth(String tokenString, Credentials credentials) {
        System.out.println(tokenString);
        Optional<Token> optionalToken = Token.fromTokenString(tokenString);
        return optionalToken.isPresent() && auth(optionalToken.get(), credentials);
    }

    public Token getServiceToken(Credentials serviceCredentials) {
        return new Token(serviceCredentials, Duration.MAX);
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
