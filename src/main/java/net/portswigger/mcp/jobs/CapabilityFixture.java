package net.portswigger.mcp.jobs;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/** A run-scoped loopback target. Observations alone do not attest Burp's tool source. */
public final class CapabilityFixture implements AutoCloseable {
    private final HttpServer server;
    private final String prefix = "/" + UUID.randomUUID();
    private String pending;
    private int accepted;

    public CapabilityFixture() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(prefix + "/", this::handle);
        server.start();
    }

    public URI baseUri() {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + prefix + "/");
    }

    public synchronized int acceptedChallenges() {
        return accepted;
    }

    /** Operator entry point for observing a bounded local run from a terminal. */
    public static void main(String[] args) throws Exception {
        try (CapabilityFixture fixture = new CapabilityFixture()) {
            System.out.println("Local fixture: " + fixture.baseUri());
            System.out.println("GET issue, then POST verify with header X-Fixture-Token.");
            System.out.println("Press Enter to stop and display accepted one-time tokens.");
            System.in.read();
            System.out.println("Accepted one-time tokens: " + fixture.acceptedChallenges());
        }
    }

    private synchronized void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            String path = exchange.getRequestURI().getRawPath();
            int status = 404;
            String body = "";
            if (path.equals(prefix + "/issue") && "GET".equals(exchange.getRequestMethod())) {
                pending = UUID.randomUUID().toString();
                body = pending;
                status = 200;
            } else if (path.equals(prefix + "/verify") && "POST".equals(exchange.getRequestMethod())) {
                String token = exchange.getRequestHeaders().getFirst("X-Fixture-Token");
                status = 403;
                if (pending != null && pending.equals(token)) {
                    pending = null;
                    accepted++;
                    status = 200;
                    body = "accepted";
                }
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Cache-Control", "no-store");
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
        }
    }

    public void close() {
        server.stop(0);
    }
}
