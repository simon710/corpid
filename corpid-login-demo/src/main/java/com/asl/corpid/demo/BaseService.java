package com.asl.corpid.demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public abstract class BaseService {
    protected static final ObjectMapper MAPPER = new ObjectMapper();

    protected static void sendText(HttpExchange exchange, int status, String body, String contentType) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    protected static void sendJson(HttpExchange exchange, int status, ObjectNode json) throws IOException {
        sendText(exchange, status, MAPPER.writeValueAsString(json), "application/json; charset=utf-8");
    }

    protected static String loadResource(String path) {
        try (var in = BaseService.class.getResourceAsStream(path)) {
            if (in == null) {
                throw new IllegalStateException("Resource not found: " + path);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new UncheckedIOException("Failed to load resource: " + path, ex);
        }
    }

    protected static Map<String, String> parseQuery(URI uri) {
        Map<String, String> result = new HashMap<>();
        String raw = uri.getRawQuery();
        if (raw == null || raw.isBlank()) {
            return result;
        }
        Arrays.stream(raw.split("&"))
            .map(part -> part.split("=", 2))
            .forEach(kv -> {
                String key = urlDecode(kv[0]);
                String value = kv.length > 1 ? urlDecode(kv[1]) : "";
                result.put(key, value);
            });
        return result;
    }

    protected static String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private static String urlDecode(String value) {
        // URLDecoder treats '+' as space (form semantics). Query params from callback may contain
        // literal '+' in authorization codes, so preserve plus by escaping it first.
        return URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8);
    }
}