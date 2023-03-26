package sirup.service.auth;

import sirup.service.auth.rpc.AuthServer;
import sirup.service.log.rpc.client.LogClient;

import java.io.IOException;
import java.util.logging.Logger;

import static spark.Spark.*;

public class Main {
    public static void main(String[] args) throws IOException, InterruptedException {
        LogClient.init("localhost", 2102);
        final AuthServer server = new AuthServer();
        server.start();
        server.blockUntilShutdown();
        //start();
    }

    public static void start() {
        final AuthController authController = new AuthController();

        get("/token", authController::getToken);
        get("/auth", authController::auth);

        Logger.getLogger(Main.class.getName()).info("AuthService Running");
    }
}
