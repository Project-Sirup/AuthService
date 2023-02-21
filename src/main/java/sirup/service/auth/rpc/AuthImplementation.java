package sirup.service.auth.rpc;

import io.grpc.stub.StreamObserver;
import sirup.service.auth.crypt.CryptB64;
import sirup.service.auth.crypt.CryptRSA;
import sirup.service.auth.crypt.ICrypt;
import sirup.service.auth.util.Authenticator;
import sirup.service.auth.util.Credentials;
import sirup.service.auth.util.Token;
import sirup.service.auth.rpc.proto.*;

import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

public class AuthImplementation extends SirupAuthGrpc.SirupAuthImplBase {

    private final Authenticator auth;
    private final Logger logger = Logger.getLogger(AuthImplementation.class.getName());

    public AuthImplementation() {
        ICrypt crypt;
        try {
            crypt = new CryptRSA();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            crypt = new CryptB64();
            e.printStackTrace();
        }
        this.auth = new Authenticator(Authenticator.Policy.DEFAULT, crypt);
    }

    @Override
    public void token(TokenRequest request, StreamObserver<TokenResponse> responseObserver) {
        logger.info("getToken");
        Credentials credentials = new Credentials(
                request.getCredentials().getUsername(),
                request.getCredentials().getPassword(),
                "");
        Token token = auth.getToken(credentials);
        TokenResponse tokenResponse = TokenResponse.newBuilder()
                .setToken(token.toTokenString())
                .build();
        responseObserver.onNext(tokenResponse);
        responseObserver.onCompleted();
    }

    @Override
    public void auth(AuthRequest request, StreamObserver<AuthResponse> responseObserver) {
        logger.info("auth");
        AuthResponse.Builder authResponseBuilder = AuthResponse.newBuilder();
        try {
            Token token = Token.fromTokenString(request.getToken());
            boolean isValid = auth.auth(token);
            authResponseBuilder.setTokenValid(isValid);
        } catch (IllegalArgumentException iae) {
            authResponseBuilder.setTokenValid(false)
                    .setError(ErrorRpc.newBuilder()
                            .setStatus(0)
                            .setErrorMessage("Invalid Token!"));
        }
        responseObserver.onNext(authResponseBuilder.build());
        responseObserver.onCompleted();
    }
}
