package sirup.service.auth.util;

import io.github.cdimascio.dotenv.Dotenv;

public class Env {
    public static final String PRIVATE_KEY;
    public static final String DUMMY_KEY = "Dumdum";
    public static final int PORT;
    static {
        Dotenv dotenv = Dotenv.load();
        PRIVATE_KEY = dotenv.get("PRIVATE_KEY");
        PORT = Integer.parseInt(dotenv.get("PORT"));
    }
}
