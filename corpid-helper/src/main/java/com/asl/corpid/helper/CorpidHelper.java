package com.asl.corpid.helper;

import com.asl.corpid.helper.model.CekInfo;
import com.asl.corpid.helper.model.CorpidTokenResponse;
import com.asl.corpid.helper.model.IamTokenResponse;
import com.asl.corpid.helper.model.QrRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class CorpidHelper {
    private static final String SIGNATURE_METHOD = "HmacSHA256";

    private final CorpidConfig config;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;
    private final PrivateKey kekPrivateKey;

    private final Map<String, CekInfo> cekByClientId = new ConcurrentHashMap<>();

    public CorpidHelper(CorpidConfig config) {
        this.config = config;
        this.objectMapper = new ObjectMapper();
        this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(20)).build();
        if (config.getKekPrivateKey() != null && !config.getKekPrivateKey().isBlank()) {
            this.kekPrivateKey = CryptoUtils.loadPrivateKeyFromPkcs8(config.getKekPrivateKey());
        } else {
            this.kekPrivateKey = CryptoUtils.loadPrivateKeyFromP12(config.getKekP12Path(), config.getKekPassword());
        }
    }

    public String buildIamAuthQrUrl(QrRequest request) {
        return config.getIamDomain() + "/api/v1/auth/getQR?" + request.toQueryString(config.getIamClientId());
    }

    public synchronized CekInfo requestCek() {
        return requestCek(config.getClientId(), config.getClientSecret());
    }

    private synchronized CekInfo requestCek(String clientId, String clientSecret) {
        String body = "";
        String url = config.getCorpidDomain() + "/api/v1/security/getKey";
        JsonNode root = postJson(
            url,
            createSignedHeaders(clientId, clientSecret, body, true),
            null
        );
        if (isSignatureVerifyError(root)) {
            root = postJson(
                url,
                createSignedHeaders(clientId, clientSecret, body, false),
                null
            );
        }
        ensureSuccess(root);

        JsonNode content = root.path("content");
        if (content.isMissingNode()) {
            throw new CorpidException("Missing content in getKey response");
        }

        String encryptedKeyBase64 = text(content, "secretKey");
        long issueAt = content.path("issueAt").asLong();
        long expiresIn = content.path("expiresIn").asLong();

        byte[] cek = CryptoUtils.decryptRsaBase64(encryptedKeyBase64, kekPrivateKey);
        long expiresAt = expiresIn > 1_000_000_000_000L ? expiresIn : issueAt + expiresIn;
        CekInfo newCek = new CekInfo(cek, issueAt, expiresAt);
        cekByClientId.put(clientId, newCek);
        return newCek;
    }

    public synchronized void revokeCek() {
        String body = "";
        SignedHeaders signed = createSignedHeaders(config.getClientId(), config.getClientSecret(), body);
        JsonNode root = postJson(
                config.getCorpidDomain() + "/api/v1/security/revokeKey",
                signed,
                null
        );
        ensureSuccess(root);
        cekByClientId.remove(config.getClientId());
    }

    public IamTokenResponse exchangeIamToken(String authCode) {
        CorpidException lastError = null;
        for (String candidate : iamCodeCandidates(authCode)) {
            try {
                return exchangeIamTokenInternal(candidate, true);
            } catch (CorpidException ex) {
                lastError = ex;
                if (!isIamDecryptError(ex)) {
                    throw ex;
                }
            }
        }
        throw lastError == null ? new CorpidException("Failed to exchange iAM token") : lastError;
    }

    private IamTokenResponse exchangeIamTokenInternal(String authCode, boolean retryOnce) {
        CekInfo cekInfo = ensureCek(config.getIamClientId(), config.getIamClientSecret());

        Map<String, Object> payload = new HashMap<>();
        payload.put("code", authCode);
        payload.put("grantType", "authorization_code");

        String clearJson = writeJson(payload);
        String encryptedContent = CryptoUtils.encryptAesGcmBase64(
                clearJson.getBytes(StandardCharsets.UTF_8),
                cekInfo.keyBytes()
        );
        String encryptedBody = writeJson(Map.of("content", encryptedContent));

        JsonNode root = postIamGetTokenWithFallback(encryptedBody);

        String msg = firstNonBlank(root.path("msg").asText(null), root.path("message").asText(""));
        boolean cekExpired = "D30002".equals(root.path("code").asText())
                || msg.toLowerCase().contains("content encryption key not exist or expired");

        if (cekExpired && retryOnce) {
            requestCek(config.getIamClientId(), config.getIamClientSecret());
            return exchangeIamTokenInternal(authCode, false);
        }

        ensureSuccess(root);
        JsonNode content = decryptContentIfNeeded(root.path("content"), cekInfo.keyBytes());
        return new IamTokenResponse(
                text(content, "accessToken"),
                text(content, "tokenType"),
                content.path("issueAt").asLong(),
                content.path("expiresIn").asLong(),
                text(content, "openID"),
            text(content, "scope"),
            content.toPrettyString()
        );
    }

    private JsonNode postIamGetTokenWithFallback(String encryptedBody) {
        String url = config.getIamDomain() + "/api/v1/auth/getToken";
        List<ClientCredential> credentials = List.of(
                new ClientCredential(config.getIamClientId(), config.getIamClientSecret())
        );

        JsonNode lastRoot = null;
        for (ClientCredential credential : credentials) {
            JsonNode encoded = postJson(
                    url,
                    createSignedHeaders(credential.clientId(), credential.clientSecret(), encryptedBody, true),
                    encryptedBody
            );
            if (!isSignatureVerifyError(encoded)) {
                return encoded;
            }
            lastRoot = encoded;

            JsonNode raw = postJson(
                    url,
                    createSignedHeaders(credential.clientId(), credential.clientSecret(), encryptedBody, false),
                    encryptedBody
            );
            if (!isSignatureVerifyError(raw)) {
                return raw;
            }
            lastRoot = raw;
        }

        return lastRoot == null ? objectMapper.createObjectNode() : lastRoot;
    }

    private List<String> iamCodeCandidates(String authCode) {
        String base = authCode == null ? "" : authCode.trim();
        Set<String> unique = new LinkedHashSet<>();

        unique.add(base);
        unique.add(base.replace(" ", "+"));
        unique.add(base.replace("%2B", "+").replace("%2b", "+"));

        String decodedOnce = safeUrlDecodePreservePlus(base);
        unique.add(decodedOnce);
        unique.add(safeUrlDecodePreservePlus(decodedOnce));

        unique.remove("");
        return new ArrayList<>(unique);
    }

    private String safeUrlDecodePreservePlus(String value) {
        return URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8);
    }

    private boolean isIamDecryptError(CorpidException ex) {
        String msg = ex.getMessage();
        if (msg == null) {
            return false;
        }
        String normalized = msg.toLowerCase();
        return normalized.contains("code=d30004") || normalized.contains("decryption exception");
    }

    private boolean isSignatureVerifyError(JsonNode root) {
        String code = root.path("code").asText("");
        String msg = firstNonBlank(root.path("msg").asText(null), root.path("message").asText(""));
        String normalized = msg.toLowerCase();
        return "D20006".equals(code) || normalized.contains("signature verification failed");
    }

    public CorpidTokenResponse exchangeCorpidToken(String cCode) {
        return exchangeCorpidTokenInternal(cCode, true);
    }

    public CorpidTokenResponse exchangeCorpidToken(String cCode, String codeVerifier, boolean isDirectLogin) {
        return exchangeCorpidTokenInternal(cCode, codeVerifier, isDirectLogin, true);
    }

    private CorpidTokenResponse exchangeCorpidTokenInternal(
            String cCode,
            boolean retryOnce
    ) {
        return exchangeCorpidTokenInternal(cCode, null, false, retryOnce);
    }

    private CorpidTokenResponse exchangeCorpidTokenInternal(
            String cCode,
            String codeVerifier,
            boolean isDirectLogin,
            boolean retryOnce
    ) {
        CekInfo cekInfo = ensureCek();

        Map<String, Object> clearPayload = new HashMap<>();
        clearPayload.put("cAuthCode", cCode);
        clearPayload.put("grantType", "authorization_code");
        if (codeVerifier != null && !codeVerifier.isBlank()) {
            clearPayload.put("code_verifier", codeVerifier);
        }
        if (isDirectLogin) {
            clearPayload.put("isDirectLogin", true);
        }

        String clearJson = writeJson(clearPayload);
        String encryptedContent = CryptoUtils.encryptAesGcmBase64(clearJson.getBytes(StandardCharsets.UTF_8), cekInfo.keyBytes());

        String encryptedBody = writeJson(Map.of("content", encryptedContent));
        SignedHeaders signed = createSignedHeaders(config.getClientId(), config.getClientSecret(), encryptedBody);

        JsonNode root = postJson(config.getCorpidDomain() + "/api/eservice/v1/auth/getToken", signed, encryptedBody);
        String msg = firstNonBlank(root.path("msg").asText(null), root.path("message").asText(""));

        boolean cekExpired = "D30002".equals(root.path("code").asText())
                || msg.toLowerCase().contains("content encryption key not exist or expired");

        if (cekExpired && retryOnce) {
            requestCek();
            return exchangeCorpidTokenInternal(cCode, codeVerifier, isDirectLogin, false);
        }

        ensureSuccess(root);
        JsonNode content = decryptContentIfNeeded(root.path("content"), cekInfo.keyBytes());

        return new CorpidTokenResponse(
                firstNonBlank(text(content, "cAccessToken"), text(content, "accessToken")),
                text(content, "tokenType"),
                content.path("issueAt").asLong(),
                content.path("expiresIn").asLong(),
                firstNonBlank(text(content, "cOpenID"), text(content, "openID")),
                text(content, "userType"),
            firstNonBlank(text(content, "cScope"), text(content, "scope")),
            content.toPrettyString()
        );
    }

    private CekInfo ensureCek() {
        return ensureCek(config.getClientId(), config.getClientSecret());
    }

    private CekInfo ensureCek(String clientId, String clientSecret) {
        CekInfo cek = cekByClientId.get(clientId);
        long now = System.currentTimeMillis();
        if (cek == null || cek.isExpired(now + 5000)) {
            return requestCek(clientId, clientSecret);
        }
        return cek;
    }

    private JsonNode parseContentPossiblyEncrypted(JsonNode content) {
        if (content == null || content.isMissingNode() || content.isNull()) {
            return objectMapper.createObjectNode();
        }
        if (content.isObject()) {
            return content;
        }
        if (content.isTextual()) {
            CekInfo cekInfo = ensureCek();
            return decryptContentIfNeeded(content, cekInfo.keyBytes());
        }
        throw new CorpidException("Unsupported content format in response");
    }

    private SignedHeaders createSignedHeaders(String clientId, String clientSecret, String body) {
        return createSignedHeaders(clientId, clientSecret, body, true);
    }

    private SignedHeaders createSignedHeaders(String clientId, String clientSecret, String body, boolean urlEncodeSignature) {
        String nonce = CryptoUtils.generateNonce();
        long timestamp = System.currentTimeMillis();
        String safeBody = body == null ? "" : body;

        String message = clientId + SIGNATURE_METHOD + timestamp + nonce + safeBody;
        String hash = CryptoUtils.hmacSha256Base64(message, clientSecret);
        String signature = urlEncodeSignature ? CryptoUtils.urlEncode(hash) : hash;
        return new SignedHeaders(clientId, SIGNATURE_METHOD, signature, timestamp, nonce);
    }

    private JsonNode postJson(String url, SignedHeaders signedHeaders, String requestBodyOrNull) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(30))
                    .header("Content-Type", "application/json")
                    .header("clientID", signedHeaders.clientId)
                    .header("signatureMethod", signedHeaders.signatureMethod)
                    .header("signature", signedHeaders.signature)
                    .header("timestamp", String.valueOf(signedHeaders.timestamp))
                    .header("nonce", signedHeaders.nonce);

            if (requestBodyOrNull == null) {
                builder.POST(HttpRequest.BodyPublishers.noBody());
            } else {
                builder.POST(HttpRequest.BodyPublishers.ofString(requestBodyOrNull, StandardCharsets.UTF_8));
            }

            HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();
            if (status < 200 || status >= 300) {
                throw new CorpidException("HTTP " + status + " calling " + url + ": " + response.body());
            }
            return objectMapper.readTree(response.body());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new CorpidException("Interrupted while calling API: " + url, ex);
        } catch (IOException ex) {
            throw new CorpidException("Failed to call API: " + url, ex);
        }
    }

    private JsonNode decryptContentIfNeeded(JsonNode content, byte[] cek) {
        if (content == null || content.isMissingNode() || content.isNull()) {
            return objectMapper.createObjectNode();
        }
        if (content.isObject()) {
            return content;
        }
        if (content.isTextual()) {
            try {
                byte[] plain = CryptoUtils.decryptAesGcmBase64ToBytes(content.asText(), cek);
                return objectMapper.readTree(plain);
            } catch (IOException ex) {
                throw new CorpidException("Failed to parse decrypted content JSON", ex);
            }
        }
        throw new CorpidException("Unsupported content format in response");
    }

    /**
     * Call a CorpID e-service (corp domain) API with the shared HMAC-SHA256 signed
     * headers and CEK-encrypted content (when {@code encryptContent} is true).
     * Reuses the same signing + encryption machinery as the token exchange.
     */
    public JsonNode callCorpApi(String path, Map<String, Object> body, boolean encryptContent) {
        CekInfo cekInfo = ensureCek();
        String requestBody = encryptContent
                ? writeJson(Map.of("content",
                    CryptoUtils.encryptAesGcmBase64(writeJson(body).getBytes(StandardCharsets.UTF_8), cekInfo.keyBytes())))
                : writeJson(body);
        SignedHeaders signed = createSignedHeaders(config.getClientId(), config.getClientSecret(), requestBody);
        JsonNode root = postJson(config.getCorpidDomain() + path, signed, requestBody);
        ensureSuccess(root);
        return root;
    }

    private void ensureSuccess(JsonNode root) {
        String code = root.path("code").asText("");
        if ("M00000".equals(code) || "D00000".equals(code)) {
            return;
        }
        String msg = firstNonBlank(root.path("msg").asText(null), root.path("message").asText(null));
        if (msg == null || msg.isBlank()) {
            msg = root.toString();
        }
        throw new CorpidException("API failed. code=" + code + ", message=" + msg);
    }

    private String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (value.isMissingNode() || value.isNull()) {
            throw new CorpidException("Missing field: " + field);
        }
        return value.asText();
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (IOException ex) {
            throw new CorpidException("Failed to serialize JSON", ex);
        }
    }

    private String firstNonBlank(String first, String second) {
        if (first != null && !first.isBlank()) {
            return first;
        }
        return second == null ? "" : second;
    }

    private static final class SignedHeaders {
        private final String clientId;
        private final String signatureMethod;
        private final String signature;
        private final long timestamp;
        private final String nonce;

        private SignedHeaders(String clientId, String signatureMethod, String signature, long timestamp, String nonce) {
            this.clientId = clientId;
            this.signatureMethod = signatureMethod;
            this.signature = signature;
            this.timestamp = timestamp;
            this.nonce = nonce;
        }
    }

    private record ClientCredential(String clientId, String clientSecret) {
    }
}
