package app;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

public class Handler implements HttpHandler {
    private final Server server;

    public Handler(Server server) {
        this.server = server;
    }

    @Override
    public void handle(HttpExchange exchange) throws java.io.IOException {
        String query = new String(exchange.getRequestBody().readAllBytes());
        try {
            server.fetch(query);
        } catch (Exception error) {
            System.getLogger("app").log(System.Logger.Level.WARNING, query);
        }
    }
}
