package sirup.service.auth.rpc;

import io.grpc.stub.StreamObserver;
import sirup.service.auth.crypt.CryptAES;
import sirup.service.auth.crypt.CryptB64;
import sirup.service.auth.crypt.CryptRSA;
import sirup.service.auth.crypt.ICrypt;
import sirup.service.auth.util.Authenticator;
import sirup.service.auth.util.Credentials;
import sirup.service.auth.util.Token;
import sirup.service.auth.rpc.proto.*;
import sirup.service.log.rpc.client.LogClient;

import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

import static sirup.service.log.rpc.client.ColorUtil.*;

public class AuthImplementation extends SirupAuthServiceGrpc.SirupAuthServiceImplBase {

    private final Authenticator auth;
    private final LogClient logger = LogClient.getInstance();

    public AuthImplementation() {
        ICrypt crypt = new CryptB64();
        try {
            crypt = new CryptAES();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            crypt = new CryptB64();
            e.printStackTrace();
        }
        this.auth = new Authenticator(Authenticator.Policy.DEFAULT, crypt);
    }

    @Override
    public void health(HealthRequest request, StreamObserver<HealthResponse> responseObserver) {
        HealthResponse healthResponse = HealthResponse.newBuilder().setHealthCode(200).build();
        responseObserver.onNext(healthResponse);
        responseObserver.onCompleted();
    }

    @Override
    public void token(TokenRequest request, StreamObserver<TokenResponse> responseObserver) {
        String userId = request.getCredentials().getUserId();
        int systemAccess = request.getCredentials().getSystemAccess();
        Credentials credentials = new Credentials(userId, systemAccess);
        Token token = auth.getToken(credentials);
        TokenResponse tokenResponse = TokenResponse.newBuilder()
                .setToken(token.toTokenString())
                .build();
        logger.info(id(userId) + " -> " + action("getToken"));
        responseObserver.onNext(tokenResponse);
        responseObserver.onCompleted();
    }

    @Override
    public void auth(AuthRequest request, StreamObserver<AuthResponse> responseObserver) {
        String userId = request.getCredentialsRpc().getUserId();
        int systemAccess = request.getCredentialsRpc().getSystemAccess();
        AuthResponse.Builder authResponseBuilder = AuthResponse.newBuilder();
        boolean isValid = false;
        try {
            Optional<Token> optionalToken = Token.fromTokenString(request.getToken());
            System.out.println(request.getToken());
            Credentials credentials = new Credentials(userId, systemAccess);
            isValid = optionalToken.isPresent() && auth.auth(optionalToken.get(), credentials);
        } catch (IllegalArgumentException iae) {
            iae.printStackTrace();
        }
        authResponseBuilder.setTokenValid(isValid);
        logger.info(id(userId) + " -> " + action("auth") + " -> " + isValid);
        responseObserver.onNext(authResponseBuilder.build());
        responseObserver.onCompleted();
    }
}
