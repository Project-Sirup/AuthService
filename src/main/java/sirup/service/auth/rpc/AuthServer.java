package sirup.service.auth.rpc;

import io.grpc.Server;
import io.grpc.ServerBuilder;
import sirup.service.auth.util.Env;
import sirup.service.log.rpc.client.LogClient;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

public class AuthServer {
    private Server server;

    public AuthServer() {

    }

    public void start() throws IOException {
        final LogClient logger = LogClient.getInstance();

        int port = Env.PORT;
        server = ServerBuilder.forPort(port).addService(new AuthImplementation()).build();
        server.start();
        logger.info("Server started, listening on " + port);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            // Use stderr here since the logger may have been reset by its JVM shutdown hook.
            System.err.println("*** shutting down gRPC server since JVM is shutting down");
            try {
                AuthServer.this.stop();
            } catch (InterruptedException e) {
                e.printStackTrace(System.err);
            }
            System.err.println("*** server shut down");
        }));
    }

    public void stop() throws InterruptedException {
        if (server != null) {
            server.shutdown().awaitTermination(30, TimeUnit.SECONDS);
        }
    }

    public void blockUntilShutdown() throws InterruptedException {
        if (server != null) {
            server.awaitTermination();
        }
    }
}
