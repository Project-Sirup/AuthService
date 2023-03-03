package sirup.service.auth;

import com.google.gson.Gson;
import org.eclipse.jetty.http.HttpStatus;
import sirup.service.auth.crypt.CryptB64;
import sirup.service.auth.crypt.CryptRSA;
import sirup.service.auth.crypt.ICrypt;
import sirup.service.auth.util.Authenticator;
import sirup.service.auth.util.Credentials;
import sirup.service.auth.util.Token;
import spark.Request;
import spark.Response;

import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Logger;

@Deprecated
public class AuthController {

    private final Logger logger = Logger.getLogger(AuthController.class.getName());
    private final Gson gson = new Gson();
    private final Authenticator auth;

    public AuthController() {
        ICrypt crypt;
        try {
            crypt = new CryptRSA();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            crypt = new CryptB64();
            e.printStackTrace();
        }
        this.auth = new Authenticator(Authenticator.Policy.DEFAULT, crypt);
    }

    public Object getToken(Request request, Response response) {
        Credentials credentials = gson.fromJson(request.body(), Credentials.class);
        logger.info("getToken");
        response.type("application/json");
        Token token = auth.getToken(credentials);
        response.body(gson.toJson(new AuthResponse(200, new HashMap<>(){{put("token",token.toTokenString());}})));
        return response.body();
    }

    public Object auth(Request request, Response response) {
        AuthRequest authRequest = gson.fromJson(request.body(), AuthRequest.class);
        logger.info("auth");
        response.type("application/json");
        AuthResponse authResponse;
        try {
            Optional<Token> optionalToken = Token.fromTokenString(authRequest.token);
            boolean isAuth = optionalToken.isPresent() && auth.auth(optionalToken.get(), authRequest.userID());
            int code = isAuth ? HttpStatus.OK_200 : HttpStatus.BAD_REQUEST_400;
            authResponse = new AuthResponse(code,
                    new HashMap<>(){{
                        put("valid",isAuth);
                    }});
        }
        catch (IllegalArgumentException iae) {
            authResponse = new AuthResponse(
                    HttpStatus.BAD_REQUEST_400,
                    new HashMap<>(){{
                        put("valid",false);
                    }});
        }
        response.status(authResponse.status);
        response.body(gson.toJson(authResponse));
        return response.body();
    }
    private static record AuthRequest(String token, String userID){}
    private static record AuthResponse(int status, Map<String,Object> body){}
}
