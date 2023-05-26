package sirup.service.auth.util;

public class Env {
    public static final int AUTH_PORT;
    public static final String PRIVATE_KEY;
    public static final String DUMMY_KEY = "Dumdum";
    static {
        AUTH_PORT = Integer.parseInt(System.getenv("AUTH_PORT"));
        PRIVATE_KEY = System.getenv("PRIVATE_KEY");
    }
}
