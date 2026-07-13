package com.asl.corpid.demo;

import com.asl.corpid.helper.CorpidConfig;
import com.asl.corpid.helper.CorpidException;
import com.asl.corpid.helper.CorpidHelper;
import com.asl.corpid.helper.model.CorpidTokenResponse;
import com.asl.corpid.helper.model.IamTokenResponse;
import com.asl.corpid.helper.model.QrRequest;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class LoginService extends BaseService {
    private static final SelectCompanyService SELECT_COMPANY_SERVICE = new SelectCompanyService();
    private static final PrefillService PREFILL_SERVICE = new PrefillService();

    static ObjectNode newObjectNode() {
        return MAPPER.createObjectNode();
    }

    static ObjectNode errorNode(String message) {
        ObjectNode node = MAPPER.createObjectNode();
        node.put("error", message);
        node.put("ok", false);
        return node;
    }

    static String prettyJson(Object value) {
        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(value);
        } catch (Exception ex) {
            return String.valueOf(value);
        }
    }

    public static CorpidConfig importConfig() {
        Env env = Env.load();
        return CorpidConfig.builder()
                .clientId(env.corpidClientId)
                .clientSecret(env.corpidClientSecret)
                .iamClientId(env.iamClientId)
                .iamClientSecret(env.iamClientSecret)
                .corpidDomain(env.corpidDomain)
                .iamDomain(env.iamDomain)
                .kekP12Path(env.kekP12Path)
                .kekPassword(env.kekPassword)
                .kekPrivateKey(env.kekPrivateKey)
                .build();
    }

    public static void login(CorpidConfig config) throws Exception {
        Env env = Env.load();

        CorpidHelper helper = new CorpidHelper(config);
        ConcurrentMap<String, FlowContext> flows = new ConcurrentHashMap<>();

        HttpServer server = createServer(env, env.callbackPort);
        server.createContext("/", exchange -> handleRoot(exchange));
        server.createContext("/api/login/start", exchange -> handleStart(exchange, env, helper, flows));
        server.createContext("/start-login", exchange -> handleStartRedirect(exchange, env, helper, flows));
        server.createContext("/api/progress", exchange -> handleProgress(exchange, flows));
        server.createContext("/api/company/select", exchange -> handleCompanySelect(exchange, flows));
        server.createContext("/api/prefill", exchange -> handlePrefill(exchange, flows));
        server.createContext("/api/corp/formFilling", exchange -> handleCorpFormFilling(exchange, env, helper, flows));
        server.createContext("/api/corp/anonFormFilling", exchange -> handleCorpAnonFormFilling(exchange, env, helper, flows));
        server.createContext("/api/corp/signing", exchange -> handleCorpSigning(exchange, env, helper, flows));
        server.createContext("/api/corp/anonSigning", exchange -> handleCorpAnonSigning(exchange, env, helper, flows));
        server.createContext(env.callbackPath, exchange -> handleCallback(exchange, env, helper, flows));
        if (!env.directLoginCallbackPath.equals(env.callbackPath)) {
            server.createContext(env.directLoginCallbackPath, exchange -> handleCallback(exchange, env, helper, flows));
        }
        server.createContext("/health", exchange -> sendText(exchange, 200, "OK", "text/plain; charset=utf-8"));
        server.start();

        HttpServer callbackBridge = null;
        if (env.shouldStartDedicatedCallbackListener()) {
            callbackBridge = createServer(env, env.publicCallbackPort);
            callbackBridge.createContext(env.callbackPath, exchange -> handleCallback(exchange, env, helper, flows));
            if (!env.directLoginCallbackPath.equals(env.callbackPath)) {
                callbackBridge.createContext(env.directLoginCallbackPath, exchange -> handleCallback(exchange, env, helper, flows));
            }
            callbackBridge.createContext("/", exchange -> handleCallbackBridgeRoot(exchange, env));
            callbackBridge.createContext("/health", exchange -> sendText(exchange, 200, "OK", "text/plain; charset=utf-8"));
            callbackBridge.start();
        }

        String callbackUri = env.callbackUri(LoginMode.DIFFERENT_DEVICE);
        String directLoginCallbackUri = env.callbackUri(LoginMode.DIRECT_LOGIN);
        System.out.println("CorpID login demo started.");
        System.out.println("Open UI in browser: " + env.localBaseUrl() + "/");
        System.out.println("Callback endpoint: " + callbackUri);
        System.out.println("Direct login callback endpoint: " + directLoginCallbackUri);
        if (callbackBridge != null) {
            System.out.println("Dedicated callback listener started on port: " + env.publicCallbackPort);
        }
    }

    private static HttpServer createServer(Env env, int listenPort) throws IOException {
        if ("https".equalsIgnoreCase(env.serverScheme)) {
            HttpsServer httpsServer = HttpsServer.create(new InetSocketAddress(listenPort), 0);
            httpsServer.setHttpsConfigurator(new HttpsConfigurator(buildSslContext(env)));
            return httpsServer;
        }
        return HttpServer.create(new InetSocketAddress(listenPort), 0);
    }

    private static SSLContext buildSslContext(Env env) {
        try {
            if (!Files.exists(env.tlsKeystorePath)) {
                throw new IllegalArgumentException("TLS keystore not found: " + env.tlsKeystorePath);
            }

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (var in = Files.newInputStream(env.tlsKeystorePath)) {
                keyStore.load(in, env.tlsKeystorePassword.toCharArray());
            }

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, env.tlsKeyPassword.toCharArray());

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
            return sslContext;
        } catch (IOException | GeneralSecurityException ex) {
            throw new IllegalStateException("Failed to initialize HTTPS server", ex);
        }
    }

    private static void handleRoot(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method Not Allowed", "text/plain; charset=utf-8");
            return;
        }
        String html = loadResource("/web/login.html");
        sendText(exchange, 200, html, "text/html; charset=utf-8");
    }

    private static void handleStart(
            HttpExchange exchange,
            Env env,
            CorpidHelper helper,
            ConcurrentMap<String, FlowContext> flows
    ) throws IOException {
        String method = exchange.getRequestMethod();
        if (!"POST".equalsIgnoreCase(method) && !"GET".equalsIgnoreCase(method)) {
            sendText(exchange, 405, "Method Not Allowed", "text/plain; charset=utf-8");
            return;
        }

        // For some HTTPS client stacks, draining request body on POST prevents abrupt TLS close.
        if ("POST".equalsIgnoreCase(method)) {
            try (var in = exchange.getRequestBody()) {
                in.readAllBytes();
            }
        }

        try {
            String userAgent = exchange.getRequestHeaders().getFirst("User-Agent");
            LoginMode mode = LoginMode.resolve(parseQuery(exchange.getRequestURI()).get("mode"), userAgent);
            StartPayload payload = createStartPayload(env, helper, flows, mode, userAgent);

            ObjectNode root = MAPPER.createObjectNode();
            root.put("state", payload.state);
            root.put("mode", payload.flow.mode.key);
            root.put("loginUrl", payload.loginUrl);
            root.set("progress", payload.flow.snapshot());

            sendJson(exchange, 200, root);
        } catch (Throwable ex) {
            ObjectNode error = MAPPER.createObjectNode();
            error.put("error", "failed_to_build_login_url");
            error.put("message", ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage());
            sendJson(exchange, 500, error);
        }
    }

    private static void handleStartRedirect(
            HttpExchange exchange,
            Env env,
            CorpidHelper helper,
            ConcurrentMap<String, FlowContext> flows
    ) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method Not Allowed", "text/plain; charset=utf-8");
            return;
        }

        try {
            String userAgent = exchange.getRequestHeaders().getFirst("User-Agent");
            LoginMode mode = LoginMode.resolve(parseQuery(exchange.getRequestURI()).get("mode"), userAgent);
            StartPayload payload = createStartPayload(env, helper, flows, mode, userAgent);
            String htmlUrl = escapeHtml(payload.loginUrl);
            String jsUrl = escapeJs(payload.loginUrl);
            String html = "<!doctype html><html><head><meta charset='utf-8'><title>Redirecting...</title>"
                    + "<meta http-equiv='refresh' content='0; url=" + htmlUrl + "'>"
                    + "</head><body style='font-family:Segoe UI,sans-serif;padding:24px'>"
                    + "Redirecting to iAM Smart login..."
                    + "<script>location.replace('" + jsUrl + "');</script>"
                    + "</body></html>";
            sendText(exchange, 200, html, "text/html; charset=utf-8");
        } catch (Throwable ex) {
            sendText(exchange, 500, "Failed to start login: " + ex.getMessage(), "text/plain; charset=utf-8");
        }
    }

    private static String escapeHtml(String value) {
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private static String escapeJs(String value) {
        return value
                .replace("\\", "\\\\")
                .replace("'", "\\'");
    }

    private static StartPayload createStartPayload(
            Env env,
            CorpidHelper helper,
            ConcurrentMap<String, FlowContext> flows,
            LoginMode mode,
            String userAgent
    ) {
        String state = env.fixedState == null || env.fixedState.isBlank()
                ? UUID.randomUUID().toString().replace("-", "")
                : env.fixedState;
        FlowContext flow = new FlowContext(state, mode);
        flow.markRunning(1, "Build login request");

        String callbackUri = env.callbackUri(mode);
        QrRequest qrRequest = QrRequest.builder()
            .source(resolveSource(env, mode, userAgent))
                .redirectUri(callbackUri)
                .scope(env.scope)
            .cScope(env.cScope)
                .state(state)
            .brokerPage(resolveBrokerPage(env, mode))
                .build();

        String loginUrl = helper.buildIamAuthQrUrl(qrRequest);
        flow.markRunning(2, "Redirect to auth page");
        flows.put(state, flow);
        return new StartPayload(state, loginUrl, flow);
    }

    private static void handleProgress(HttpExchange exchange, ConcurrentMap<String, FlowContext> flows) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method Not Allowed", "text/plain; charset=utf-8");
            return;
        }
        String state = parseQuery(exchange.getRequestURI()).get("state");
        if (state == null || state.isBlank()) {
            sendText(exchange, 400, "Missing state", "text/plain; charset=utf-8");
            return;
        }

        FlowContext flow = flows.get(state);
        if (flow == null) {
            sendText(exchange, 404, "State not found", "text/plain; charset=utf-8");
            return;
        }

        ObjectNode root = MAPPER.createObjectNode();
        root.put("state", state);
        root.set("progress", flow.snapshot());
        root.set("companySelection", flow.companySelectionSnapshot());
        if (flow.shouldExposeTokenSummary()) {
            root.put("tokenSummary", flow.tokenSummary());
        }
        sendJson(exchange, 200, root);
    }

    private static void handleCompanySelect(HttpExchange exchange, ConcurrentMap<String, FlowContext> flows) throws IOException {
        String method = exchange.getRequestMethod();
        if (!"POST".equalsIgnoreCase(method) && !"GET".equalsIgnoreCase(method)) {
            sendText(exchange, 405, "Method Not Allowed", "text/plain; charset=utf-8");
            return;
        }

        Map<String, String> query = parseQuery(exchange.getRequestURI());
        String state = query.get("state");
        String company = query.get("company");

        if (state == null || state.isBlank() || company == null || company.isBlank()) {
            sendText(exchange, 400, "Missing state/company", "text/plain; charset=utf-8");
            return;
        }

        FlowContext flow = flows.get(state);
        if (flow == null) {
            sendText(exchange, 404, "State not found", "text/plain; charset=utf-8");
            return;
        }

        if (!flow.requiresCompanySelection) {
            sendText(exchange, 409, "Company selection not required", "text/plain; charset=utf-8");
            return;
        }

        if (!flow.companyOptions.contains(company)) {
            sendText(exchange, 400, "Invalid company", "text/plain; charset=utf-8");
            return;
        }

        flow.selectedCompany = company;
        flow.requiresCompanySelection = false;
        flow.markRunning(7, "Select company completed; waiting for Prefill / Anon Prefill action");

        ObjectNode root = MAPPER.createObjectNode();
        root.put("state", state);
        root.set("progress", flow.snapshot());
        root.set("companySelection", flow.companySelectionSnapshot());
        root.put("tokenSummary", flow.tokenSummary());
        sendJson(exchange, 200, root);
    }

    private static void handlePrefill(HttpExchange exchange, ConcurrentMap<String, FlowContext> flows) throws IOException {
        String method = exchange.getRequestMethod();
        if (!"POST".equalsIgnoreCase(method) && !"GET".equalsIgnoreCase(method)) {
            sendText(exchange, 405, "Method Not Allowed", "text/plain; charset=utf-8");
            return;
        }

        Map<String, String> query = parseQuery(exchange.getRequestURI());
        String state = query.get("state");
        String type = query.getOrDefault("type", "normal");
        boolean anonymous = "anon".equalsIgnoreCase(type);

        if (state == null || state.isBlank()) {
            sendText(exchange, 400, "Missing state", "text/plain; charset=utf-8");
            return;
        }

        FlowContext flow = flows.get(state);
        if (flow == null) {
            sendText(exchange, 404, "State not found", "text/plain; charset=utf-8");
            return;
        }

        if (flow.corpidToken == null) {
            sendText(exchange, 409, "CorpID token not available", "text/plain; charset=utf-8");
            return;
        }

        if (flow.selectedCompany == null || flow.selectedCompany.isBlank()) {
            sendText(exchange, 409, "Company not selected", "text/plain; charset=utf-8");
            return;
        }

        flow.markRunning(7, anonymous ? "Run Anon Prefill" : "Run Prefill");
        flow.prefillMode = anonymous ? "anon" : "normal";
        flow.prefillData = PREFILL_SERVICE.prefill(flow.corpidToken, flow.selectedCompany, anonymous);
        flow.done(7, anonymous
                ? "Login + checklist completed (select company + anon prefill)"
                : "Login + checklist completed (select company + prefill)");

        ObjectNode root = MAPPER.createObjectNode();
        root.put("state", state);
        root.set("progress", flow.snapshot());
        root.set("companySelection", flow.companySelectionSnapshot());
        root.put("tokenSummary", flow.tokenSummary());
        sendJson(exchange, 200, root);
    }

    // ---- Corp e-service APIs (form filling / signing) -------------------------------

    private static CorpApiService newCorpApiService(Env env, CorpidHelper helper) {
        return new CorpApiService(helper, env.corpidDomain);
    }

    private static String corpSource(Env env) {
        return env.source == null || env.source.isBlank() ? "PC_Browser" : env.source;
    }

    private static String corpRedirectUri(Env env) {
        return env.callbackUri(LoginMode.DIFFERENT_DEVICE);
    }

    private static CorpApiService.SignType parseSignType(String value) {
        if (value == null || value.isBlank()) {
            return CorpApiService.SignType.PERSONAL_SIGN;
        }
        try {
            return CorpApiService.SignType.valueOf(value.trim().toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return CorpApiService.SignType.PERSONAL_SIGN;
        }
    }

    private static ObjectNode respondCorpApi(HttpExchange exchange, FlowContext flow, CorpApiService.CorpApiResult result)
            throws IOException {
        if (result.ok()) {
            flow.markCorpApi(result.api(), result.responseJson());
        } else {
            flow.markCorpApiError(result.api(), result.error());
        }
        ObjectNode root = MAPPER.createObjectNode();
        root.put("state", flow.state);
        root.set("progress", flow.snapshot());
        root.set("companySelection", flow.companySelectionSnapshot());
        if (flow.shouldExposeTokenSummary()) {
            root.put("tokenSummary", flow.tokenSummary());
        }
        root.set("corpApi", result.toJson());
        sendJson(exchange, result.ok() ? 200 : 422, root);
        return root;
    }

    private static void handleCorpFormFilling(
            HttpExchange exchange, Env env, CorpidHelper helper, ConcurrentMap<String, FlowContext> flows
    ) throws IOException {
        if (handlePreflight(exchange)) return;
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method Not Allowed", "text/plain; charset=utf-8");
            return;
        }
        String state = parseQuery(exchange.getRequestURI()).get("state");
        FlowContext flow = state == null ? null : flows.get(state);
        if (flow == null) {
            sendText(exchange, 404, "State not found", "text/plain; charset=utf-8");
            return;
        }
        CorpApiService.CorpApiResult result = newCorpApiService(env, helper).formFilling(
                flow.corpidToken, flow.state, corpSource(env), corpRedirectUri(env),
                java.util.List.of("corpName", "brNo"), java.util.List.of("corpNameEn", "brNo"));
        respondCorpApi(exchange, flow, result);
    }

    private static void handleCorpAnonFormFilling(
            HttpExchange exchange, Env env, CorpidHelper helper, ConcurrentMap<String, FlowContext> flows
    ) throws IOException {
        if (handlePreflight(exchange)) return;
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendJson(exchange, 405, errorNode("Method Not Allowed"));
            return;
        }
        try {
            // Anonymous form filling does NOT require a CorpID login / state.
            String state = parseQuery(exchange.getRequestURI()).get("state");
            FlowContext flow = (state == null || state.isBlank()) ? new FlowContext("anon", LoginMode.DIFFERENT_DEVICE) : flows.getOrDefault(state, new FlowContext(state, LoginMode.DIFFERENT_DEVICE));
            CorpApiService.CorpApiResult result = newCorpApiService(env, helper).anonFormFilling(
                    corpSource(env), corpRedirectUri(env),
                    java.util.List.of("corpName", "brNo"), java.util.List.of("corpNameEn", "brNo"));
            respondCorpApi(exchange, flow, result);
        } catch (Exception ex) {
            // Never let an uncaught exception reset the connection (which the browser
            // reports as "Failed to fetch" with 0 bytes). Always return JSON so the
            // frontend can render the real error.
            sendJson(exchange, 500, errorNode("anonFormFilling error: " + ex.getMessage()));
        }
    }

    private static void handleCorpSigning(
            HttpExchange exchange, Env env, CorpidHelper helper, ConcurrentMap<String, FlowContext> flows
    ) throws IOException {
        if (handlePreflight(exchange)) return;
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method Not Allowed", "text/plain; charset=utf-8");
            return;
        }
        Map<String, String> query = parseQuery(exchange.getRequestURI());
        String state = query.get("state");
        String signType = query.getOrDefault("signType", "PERSONAL_SIGN");
        String documentName = query.getOrDefault("documentName", "Demo Document");
        FlowContext flow = state == null ? null : flows.get(state);
        if (flow == null) {
            sendText(exchange, 404, "State not found", "text/plain; charset=utf-8");
            return;
        }
        CorpApiService.CorpApiResult result = newCorpApiService(env, helper).signing(
                flow.corpidToken, flow.state, corpSource(env), corpRedirectUri(env), parseSignType(signType), documentName);
        respondCorpApi(exchange, flow, result);
    }

    private static void handleCorpAnonSigning(
            HttpExchange exchange, Env env, CorpidHelper helper, ConcurrentMap<String, FlowContext> flows
    ) throws IOException {
        if (handlePreflight(exchange)) return;
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendJson(exchange, 405, errorNode("Method Not Allowed"));
            return;
        }
        // Anonymous signing does NOT require a CorpID login / state.
        Map<String, String> query = parseQuery(exchange.getRequestURI());
        String state = query.get("state");
        String signType = query.getOrDefault("signType", "PERSONAL_SIGN");
        String hkic = query.getOrDefault("hkic", "");
        String documentName = query.getOrDefault("documentName", "Demo Document");
        FlowContext flow = (state == null || state.isBlank()) ? new FlowContext("anon", LoginMode.DIFFERENT_DEVICE) : flows.getOrDefault(state, new FlowContext(state, LoginMode.DIFFERENT_DEVICE));
        CorpApiService.CorpApiResult result = newCorpApiService(env, helper).anonSigning(
                corpSource(env), corpRedirectUri(env), parseSignType(signType), hkic, documentName);
        respondCorpApi(exchange, flow, result);
    }

    private static void handleCallback(
            HttpExchange exchange,
            Env env,
            CorpidHelper helper,
            ConcurrentMap<String, FlowContext> flows
    ) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method Not Allowed", "text/plain; charset=utf-8");
            return;
        }

        Map<String, String> query = parseQuery(exchange.getRequestURI());
        String state = query.get("state");
        String iamCode = query.get("code");
        String cAuthCode = firstNonBlank(
            query.get("cAuthCode"),
            query.get("cCode"),
            query.get("corpMockCode")
        );
        String cErrorCode = query.get("cError_code");
        String iamErrorCode = query.get("error_code");

        FlowContext flow = state == null ? null : flows.get(state);
        if (flow == null) {
            sendText(exchange, 400, "Unknown state", "text/plain; charset=utf-8");
            return;
        }

        flow.markRunning(3, "Callback received");

        if ((cErrorCode != null && !cErrorCode.isBlank()) || (iamErrorCode != null && !iamErrorCode.isBlank())) {
            String codeText = (cErrorCode != null && !cErrorCode.isBlank())
                    ? "cError_code=" + cErrorCode
                    : "error_code=" + iamErrorCode;
            flow.fail(3, "Authorization denied or login failed: " + codeText);
            sendText(exchange, 200, callbackHtml(env, flow), "text/html; charset=utf-8");
            return;
        }

        try {
            if (flow.mode == LoginMode.DIRECT_LOGIN) {
                handleDirectLoginCallback(env, helper, flow, cAuthCode, state);
            } else {
                handleStandardCallback(env, helper, flow, iamCode, cAuthCode, state);
            }
        } catch (CorpidException ex) {
            String message = ex.getMessage() == null ? "CorpidException without message" : ex.getMessage();
            System.err.println("Login flow failed at step " + flow.currentStep + ", state=" + state + ": " + message);
            ex.printStackTrace(System.err);
            flow.fail(flow.currentStep, message);
        } catch (Exception ex) {
            String message = ex.getMessage() == null ? ex.getClass().getName() : ex.getMessage();
            System.err.println("Login flow unhandled error at step " + flow.currentStep + ", state=" + state + ": " + message);
            ex.printStackTrace(System.err);
            flow.fail(flow.currentStep, "Unhandled error: " + message);
        }

        sendText(exchange, 200, callbackHtml(env, flow), "text/html; charset=utf-8");
    }

    private static void handleStandardCallback(
            Env env,
            CorpidHelper helper,
            FlowContext flow,
            String iamCode,
            String cAuthCode,
            String state
    ) {
        if (iamCode == null || iamCode.isBlank()) {
            flow.fail(3, "Callback missing required parameter: code");
            return;
        }

        flow.markRunning(4, "Exchange iAM token via helper library");
        IamTokenResponse iamToken = helper.exchangeIamToken(iamCode);
        flow.iamToken = iamToken;
        // Login is considered successful once iAM token is obtained.
        flow.done(4, "Login completed with iAM Smart accessToken");

        if (cAuthCode == null || cAuthCode.isBlank()) {
            flow.markCorpidNotAvailable("Callback missing cAuthCode; iAM token exchanged, CorpID token exchange skipped");
            return;
        }

        try {
            flow.markRunning(5, "Exchange CorpID token via helper library (optional)");
            CorpidTokenResponse corpidToken = helper.exchangeCorpidToken(cAuthCode);

            flow.corpidToken = corpidToken;
            runPostLoginChecklist(flow);
        } catch (CorpidException ex) {
            String message = ex.getMessage() == null ? "CorpidException without message" : ex.getMessage();
            System.err.println("Optional CorpID exchange failed after iAM login, state=" + state + ": " + message);
            ex.printStackTrace(System.err);
            flow.markCorpidNotAvailable("CorpID token exchange failed (iAM login unaffected): " + message);
            flow.done(4, "Login completed with iAM Smart accessToken");
        } catch (Exception ex) {
            String message = ex.getMessage() == null ? ex.getClass().getName() : ex.getMessage();
            System.err.println("Optional CorpID exchange unhandled error after iAM login, state=" + state + ": " + message);
            ex.printStackTrace(System.err);
            flow.markCorpidNotAvailable("CorpID token exchange failed (iAM login unaffected): " + message);
            flow.done(4, "Login completed with iAM Smart accessToken");
        }
    }

    private static void handleDirectLoginCallback(
            Env env,
            CorpidHelper helper,
            FlowContext flow,
            String cAuthCode,
            String state
    ) {
        if (cAuthCode == null || cAuthCode.isBlank()) {
            flow.fail(3, "Callback missing required parameter for directLogin: cAuthCode");
            return;
        }
        if (env.directLoginCodeVerifier == null || env.directLoginCodeVerifier.isBlank()) {
            flow.fail(3, "Missing DIRECT_LOGIN_CODE_VERIFIER env var for directLogin");
            return;
        }

        flow.markRunning(5, "Exchange CorpID token via helper library (directLogin)");
        CorpidTokenResponse corpidToken = helper.exchangeCorpidToken(cAuthCode, env.directLoginCodeVerifier, true);
        flow.corpidToken = corpidToken;
        runPostLoginChecklist(flow);
        System.out.println("Direct login completed, state=" + state);
    }

    private static void runPostLoginChecklist(FlowContext flow) {
        flow.markRunning(7, "Select company");
        SelectCompanyService.SelectCompanyDecision decision = SELECT_COMPANY_SERVICE.buildDecision(flow.corpidToken);
        flow.corpCount = decision.corpCount();
        flow.companyOptions = decision.companyOptions();
        flow.selectedCompany = decision.selectedCompany();
        flow.requiresCompanySelection = decision.requiresSelection();
        flow.prefillData = null;
        flow.prefillMode = "";

        if (flow.requiresCompanySelection) {
            flow.markRunning(7, "Select company (等待使用者選擇)");
            return;
        }

        flow.markRunning(7, "Select company completed; waiting for Prefill / Anon Prefill action");
    }

    private static String callbackHtml(Env env, FlowContext flow) {
        String safeState = flow.state == null ? "" : flow.state;
        String safeMode = flow.mode.key;
        String backToUi = env.localBaseUrl() + "/?state=" + safeState + "&mode=" + safeMode;
        return "<!doctype html><html><head><meta charset='utf-8'><title>Callback</title>"
                + "<meta http-equiv='refresh' content='1; url=" + backToUi + "'>"
                + "</head><body style='font-family:Segoe UI,sans-serif;padding:24px'>"
                + "Callback received. Returning to progress page..."
                + "<script>setTimeout(function(){location.href='" + backToUi + "';},900);</script>"
                + "</body></html>";
    }

    private static void handleCallbackBridgeRoot(HttpExchange exchange, Env env) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method Not Allowed", "text/plain; charset=utf-8");
            return;
        }
        String state = parseQuery(exchange.getRequestURI()).getOrDefault("state", "");
        LoginMode mode = LoginMode.fromQuery(parseQuery(exchange.getRequestURI()).get("mode"));
        String target = env.localBaseUrl() + "/?state=" + state + "&mode=" + mode.key;
        String html = "<!doctype html><html><head><meta charset='utf-8'><title>Redirecting...</title>"
                + "<meta http-equiv='refresh' content='0; url=" + target + "'>"
                + "</head><body style='font-family:Segoe UI,sans-serif;padding:24px'>"
                + "Redirecting to login progress page..."
                + "<script>location.replace('" + target + "');</script>"
                + "</body></html>";
        sendText(exchange, 200, html, "text/html; charset=utf-8");
    }

    private static String resolveSource(Env env, LoginMode mode, String userAgent) {
        return switch (mode) {
            case SAME_DEVICE -> isAutoSource(env.sameDeviceSource)
                    ? detectBrowserSourceFromUserAgent(userAgent)
                    : env.sameDeviceSource;
            case DIFFERENT_DEVICE -> env.differentDeviceSource;
            case IN_APP_BROWSER -> isAutoSource(env.inAppBrowserSource)
                ? detectInAppBrowserSourceFromUserAgent(userAgent)
                : env.inAppBrowserSource;
            case DIRECT_LOGIN -> isAutoSource(env.directLoginSource)
                ? detectDirectLoginSourceFromUserAgent(userAgent)
                : env.directLoginSource;
        };
    }

    private static boolean isAutoSource(String value) {
        return value == null || value.isBlank() || "AUTO".equalsIgnoreCase(value);
    }

    private static String detectBrowserSourceFromUserAgent(String userAgent) {
        String ua = userAgent == null ? "" : userAgent.toLowerCase(Locale.ROOT);

        if (ua.contains("android")) {
            if (ua.contains("samsungbrowser")) {
                return "Android_Samsung";
            }
            if (ua.contains("edg")) {
                return "Android_Edge";
            }
            if (ua.contains("firefox")) {
                return "Android_Firefox";
            }
            return "Android_Chrome";
        }

        if (ua.contains("iphone") || ua.contains("ipad") || ua.contains("ios")) {
            if (ua.contains("edgios")) {
                return "iOS_Edge";
            }
            if (ua.contains("fxios")) {
                return "iOS_Firefox";
            }
            if (ua.contains("crios")) {
                return "iOS_Chrome";
            }
            return "iOS_Safari";
        }

        return "PC_Browser";
    }

    private static String detectInAppBrowserSourceFromUserAgent(String userAgent) {
        String ua = userAgent == null ? "" : userAgent.toLowerCase(Locale.ROOT);
        if (ua.contains("iphone") || ua.contains("ipad") || ua.contains("ios")) {
            return "iOS_IMS_InAppBrowser";
        }
        return "Android_IMS_InAppBrowser";
    }

    private static String detectDirectLoginSourceFromUserAgent(String userAgent) {
        String ua = userAgent == null ? "" : userAgent.toLowerCase(Locale.ROOT);
        if (ua.contains("iphone") || ua.contains("ipad") || ua.contains("ios")) {
            return "App_Link";
        }
        return "App_Package";
    }

    private static Boolean resolveBrokerPage(Env env, LoginMode mode) {
        return switch (mode) {
            case SAME_DEVICE -> env.brokerPage;
            case DIFFERENT_DEVICE -> env.brokerPage;
            case IN_APP_BROWSER -> false;
            case DIRECT_LOGIN -> env.directLoginBrokerPage;
        };
    }

    private enum LoginMode {
        SAME_DEVICE("same_device"),
        DIFFERENT_DEVICE("different_device"),
        IN_APP_BROWSER("in_app_browser"),
        DIRECT_LOGIN("direct_login");

        private final String key;

        LoginMode(String key) {
            this.key = key;
        }

        private static LoginMode fromQuery(String modeValue) {
            String normalized = modeValue.trim().toLowerCase(Locale.ROOT);
            for (LoginMode mode : values()) {
                if (mode.key.equals(normalized)) {
                    return mode;
                }
            }
            return DIFFERENT_DEVICE;
        }

        private static LoginMode resolve(String modeValue, String userAgent) {
            if (modeValue == null || modeValue.isBlank()) {
                return isMobileUserAgent(userAgent) ? SAME_DEVICE : DIFFERENT_DEVICE;
            }
            return fromQuery(modeValue);
        }
    }

    private static boolean isMobileUserAgent(String userAgent) {
        String ua = userAgent == null ? "" : userAgent.toLowerCase(Locale.ROOT);
        return ua.contains("android") || ua.contains("iphone") || ua.contains("ipad") || ua.contains("ios");
    }

    private static final class FlowContext {
        private final String state;
        private final LoginMode mode;
        private volatile int currentStep;
        private volatile String status;
        private volatile String detail;
        private volatile String errorMessage;
        private volatile IamTokenResponse iamToken;
        private volatile CorpidTokenResponse corpidToken;
        private volatile String corpidUnavailableReason;
        private volatile String selectedCompany;
        private volatile Map<String, String> prefillData;
        private volatile String prefillMode;
        private volatile int corpCount;
        private volatile boolean requiresCompanySelection;
        private volatile java.util.List<String> companyOptions;
        private volatile String lastCorpApi;
        private volatile String lastCorpApiResponse;
        private volatile String lastCorpApiError;

        private FlowContext(String state, LoginMode mode) {
            this.state = state;
            this.mode = mode;
            this.currentStep = 0;
            this.status = "IDLE";
            this.detail = "";
            this.errorMessage = "";
            this.prefillMode = "";
            this.corpCount = 1;
            this.requiresCompanySelection = false;
            this.companyOptions = java.util.List.of();
            this.lastCorpApi = "";
            this.lastCorpApiResponse = "";
            this.lastCorpApiError = "";
        }

        private synchronized void markRunning(int step, String detail) {
            this.currentStep = step;
            this.status = "RUNNING";
            this.detail = detail;
            this.errorMessage = "";
        }

        private synchronized void done(int step, String detail) {
            this.currentStep = step;
            this.status = "DONE";
            this.detail = detail;
            this.errorMessage = "";
        }

        private synchronized void fail(int step, String message) {
            this.currentStep = step;
            this.status = "ERROR";
            this.errorMessage = message;
        }

        private synchronized void markCorpidNotAvailable(String reason) {
            this.corpidUnavailableReason = reason;
        }

        private synchronized void markCorpApi(String api, String responseJson) {
            this.lastCorpApi = api;
            this.lastCorpApiResponse = responseJson == null ? "" : responseJson;
            this.lastCorpApiError = "";
        }

        private synchronized void markCorpApiError(String api, String error) {
            this.lastCorpApi = api;
            this.lastCorpApiResponse = "";
            this.lastCorpApiError = error == null ? "" : error;
        }

        private synchronized boolean shouldExposeTokenSummary() {
            return iamToken != null || corpidToken != null || "ERROR".equals(status);
        }

        private synchronized ObjectNode snapshot() {
            ObjectNode node = MAPPER.createObjectNode();
            node.put("state", state);
            node.put("mode", mode.key);
            node.put("currentStep", currentStep);
            node.put("status", status);
            node.put("detail", detail);
            node.put("errorMessage", errorMessage);
            node.put("hasIamToken", iamToken != null);
            node.put("hasCorpidToken", corpidToken != null);
            node.put("checklistCompleted", corpidToken != null && prefillData != null && !prefillData.isEmpty());
            node.put("corpidUnavailableReason", corpidUnavailableReason == null ? "" : corpidUnavailableReason);
            node.put("prefillMode", prefillMode == null ? "" : prefillMode);
            node.put("lastCorpApi", lastCorpApi);
            node.put("lastCorpApiResponse", lastCorpApiResponse);
            node.put("lastCorpApiError", lastCorpApiError);
            return node;
        }

        private synchronized ObjectNode companySelectionSnapshot() {
            ObjectNode node = MAPPER.createObjectNode();
            node.put("corpCount", corpCount);
            node.put("requiresSelection", requiresCompanySelection);
            node.put("selectedCompany", selectedCompany == null ? "" : selectedCompany);
            node.put("prefillReady", corpidToken != null && selectedCompany != null && !selectedCompany.isBlank());
            node.put("prefillCompleted", prefillData != null && !prefillData.isEmpty());
            var optionsNode = node.putArray("options");
            for (String option : companyOptions) {
                optionsNode.add(option);
            }
            return node;
        }

        private synchronized String tokenSummary() {
            StringBuilder sb = new StringBuilder();
            if (iamToken != null) {
                sb.append("[iAM Smart getToken content]\n")
                        .append(iamToken.rawContentJson())
                        .append("\n\n");
            }
            if (corpidToken != null) {
                sb.append("[CorpID getToken content]\n")
                        .append(corpidToken.rawContentJson())
                        .append("\n\n")
                        .append("[Checklist - select company]\n")
                        .append(selectedCompany == null ? "(not available)" : selectedCompany)
                        .append("\n\n")
                        .append("[Checklist - prefill]\n")
                        .append(prefillData == null || prefillData.isEmpty() ? "(not available)" : prefillData.toString());
                if (prefillMode != null && !prefillMode.isBlank()) {
                    sb.append("\n\n[Prefill mode]\n").append(prefillMode);
                }
            } else {
                sb.append("[CorpID getToken content]\n")
                        .append("(not available) ")
                        .append(corpidUnavailableReason == null || corpidUnavailableReason.isBlank()
                                ? "CorpID token exchange skipped or failed; check progress.errorMessage"
                                : corpidUnavailableReason);
            }
            return sb.toString();
        }
    }

    private record StartPayload(String state, String loginUrl, FlowContext flow) {
    }

    private static final class Env {
        private final String corpidClientId;
        private final String corpidClientSecret;
        private final String iamClientId;
        private final String iamClientSecret;
        private final String corpidDomain;
        private final String iamDomain;
        private final Path kekP12Path;
        private final String kekPassword;
        private final String kekPrivateKey;
        private final int callbackPort;
        private final String callbackPath;
        private final String directLoginCallbackPath;
        private final String callbackPublicBaseUrl;
        private final int publicCallbackPort;
        private final String serverScheme;
        private final Path tlsKeystorePath;
        private final String tlsKeystorePassword;
        private final String tlsKeyPassword;
        private final String source;
        private final String sameDeviceSource;
        private final String differentDeviceSource;
        private final String inAppBrowserSource;
        private final String directLoginSource;
        private final String scope;
        private final String cScope;
        private final Boolean brokerPage;
        private final Boolean directLoginBrokerPage;
        private final String directLoginCodeVerifier;
        private final String fixedState;

        private Env(
                String corpidClientId,
                String corpidClientSecret,
                String iamClientId,
                String iamClientSecret,
                String corpidDomain,
                String iamDomain,
                Path kekP12Path,
                String kekPassword,
                String kekPrivateKey,
                int callbackPort,
                String callbackPath,
                String directLoginCallbackPath,
                String callbackPublicBaseUrl,
                int publicCallbackPort,
                String serverScheme,
                Path tlsKeystorePath,
                String tlsKeystorePassword,
                String tlsKeyPassword,
                String source,
                String sameDeviceSource,
                String differentDeviceSource,
                String inAppBrowserSource,
                String directLoginSource,
                String scope,
                String cScope,
                Boolean brokerPage,
                Boolean directLoginBrokerPage,
                String directLoginCodeVerifier,
                String fixedState
        ) {
            this.corpidClientId = corpidClientId;
            this.corpidClientSecret = corpidClientSecret;
            this.iamClientId = iamClientId;
            this.iamClientSecret = iamClientSecret;
            this.corpidDomain = corpidDomain;
            this.iamDomain = iamDomain;
            this.kekP12Path = kekP12Path;
            this.kekPassword = kekPassword;
            this.kekPrivateKey = kekPrivateKey;
            this.callbackPort = callbackPort;
            this.callbackPath = callbackPath;
            this.directLoginCallbackPath = directLoginCallbackPath;
            this.callbackPublicBaseUrl = callbackPublicBaseUrl;
            this.publicCallbackPort = publicCallbackPort;
            this.serverScheme = serverScheme;
            this.tlsKeystorePath = tlsKeystorePath;
            this.tlsKeystorePassword = tlsKeystorePassword;
            this.tlsKeyPassword = tlsKeyPassword;
            this.source = source;
            this.sameDeviceSource = sameDeviceSource;
            this.differentDeviceSource = differentDeviceSource;
            this.inAppBrowserSource = inAppBrowserSource;
            this.directLoginSource = directLoginSource;
            this.scope = scope;
            this.cScope = cScope;
            this.brokerPage = brokerPage;
            this.directLoginBrokerPage = directLoginBrokerPage;
            this.directLoginCodeVerifier = directLoginCodeVerifier;
            this.fixedState = fixedState;
        }

        private static Env load() {
            String corpidClientId = required("CORPID_CLIENT_ID");
            String corpidClientSecret = required("CORPID_CLIENT_SECRET");
            String iamClientId = required("IAM_CLIENT_ID");
            String iamClientSecret = required("IAM_CLIENT_SECRET");
            String corpidDomain = required("CORPID_DOMAIN");
            String iamDomain = optional("IAM_DOMAIN", "apigw-isit.staging-eid.gov.hk");
            String kekPath = optional("KEK_P12_PATH", "doc/account-centre-kek.p12");
            String kekPassword = optional("KEK_P12_PASSWORD", "8568185550716550");
            String kekPrivateKey = optional("KEK_PRIVATE_KEY", "");
            int callbackPort = Integer.parseInt(optional("CALLBACK_PORT", "3000"));
            String callbackPath = optional("CALLBACK_PATH", "/iAMSmart/LoginCallback");
            String directLoginCallbackPath = optional("DIRECT_LOGIN_CALLBACK_PATH", "/iAMSmart/DirectLoginCallback");
            String callbackPublicBaseUrl = optional("CALLBACK_PUBLIC_BASE_URL", "");
            String serverScheme = optional("SERVER_SCHEME", "http").toLowerCase();
            int publicCallbackPort = parsePublicCallbackPort(callbackPublicBaseUrl, serverScheme);
            Path tlsKeystorePath = Path.of(optional("TLS_KEYSTORE_PATH", kekPath));
            String tlsKeystorePassword = optional("TLS_KEYSTORE_PASSWORD", kekPassword);
            String tlsKeyPassword = optional("TLS_KEY_PASSWORD", tlsKeystorePassword);
            String source = optional("LOGIN_SOURCE", "PC_Browser");
            String sameDeviceSource = optional("LOGIN_SOURCE_SAME_DEVICE", "AUTO");
            String differentDeviceSource = optional("LOGIN_SOURCE_DIFFERENT_DEVICE", source);
            String inAppBrowserSource = optional("LOGIN_SOURCE_IN_APP_BROWSER", "AUTO");
            String directLoginSource = optional("LOGIN_SOURCE_DIRECT_LOGIN", "AUTO");
            String scope = optional("LOGIN_SCOPE", "eidapi_auth eidapi_sign eidapi_profiles");
            String cScope = optional("LOGIN_C_SCOPE", "corpidapi_auth");
            Boolean brokerPage = optionalBoolean("LOGIN_BROKER_PAGE", true);
            Boolean directLoginBrokerPage = optionalBoolean("LOGIN_DIRECT_BROKER_PAGE", false);
            String directLoginCodeVerifier = optional("DIRECT_LOGIN_CODE_VERIFIER", "");
            String fixedState = optional("LOGIN_FIXED_STATE", "");

            return new Env(
                    corpidClientId,
                    corpidClientSecret,
                    iamClientId,
                    iamClientSecret,
                    corpidDomain,
                    iamDomain,
                    Path.of(kekPath),
                    kekPassword,
                    kekPrivateKey,
                    callbackPort,
                    callbackPath,
                    directLoginCallbackPath,
                    callbackPublicBaseUrl,
                    publicCallbackPort,
                    serverScheme,
                    tlsKeystorePath,
                    tlsKeystorePassword,
                    tlsKeyPassword,
                    source,
                    sameDeviceSource,
                    differentDeviceSource,
                    inAppBrowserSource,
                    directLoginSource,
                    scope,
                    cScope,
                    brokerPage,
                    directLoginBrokerPage,
                    directLoginCodeVerifier,
                    fixedState
            );
        }

        private static String required(String key) {
            String value = System.getenv(key);
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException("Missing required env var: " + key);
            }
            return value;
        }

        private static String optional(String key, String defaultValue) {
            String value = System.getenv(key);
            return (value == null || value.isBlank()) ? defaultValue : value;
        }

        private static Boolean optionalBoolean(String key, boolean defaultValue) {
            String value = System.getenv(key);
            if (value == null || value.isBlank()) {
                return defaultValue;
            }
            return "true".equalsIgnoreCase(value) || "1".equals(value) || "yes".equalsIgnoreCase(value);
        }

        private String callbackUri(LoginMode mode) {
            String path = mode == LoginMode.DIRECT_LOGIN ? directLoginCallbackPath : callbackPath;
            if (callbackPublicBaseUrl != null && !callbackPublicBaseUrl.isBlank()) {
                return normalizeBaseUrl(callbackPublicBaseUrl) + path;
            }
            return localBaseUrl() + path;
        }

        private String localBaseUrl() {
            return serverScheme + "://localhost:" + callbackPort;
        }

        private boolean shouldStartDedicatedCallbackListener() {
            if (callbackPublicBaseUrl == null || callbackPublicBaseUrl.isBlank()) {
                return false;
            }
            return publicCallbackPort > 0 && publicCallbackPort != callbackPort;
        }

        private static String normalizeBaseUrl(String baseUrl) {
            String trimmed = baseUrl.trim();
            if (trimmed.endsWith("/")) {
                return trimmed.substring(0, trimmed.length() - 1);
            }
            return trimmed;
        }

        private static int parsePublicCallbackPort(String callbackPublicBaseUrl, String serverScheme) {
            if (callbackPublicBaseUrl == null || callbackPublicBaseUrl.isBlank()) {
                return -1;
            }
            try {
                URI uri = new URI(callbackPublicBaseUrl);
                int port = uri.getPort();
                if (port > 0) {
                    return port;
                }
                String scheme = uri.getScheme();
                if (scheme == null || scheme.isBlank()) {
                    scheme = serverScheme;
                }
                return "https".equalsIgnoreCase(scheme) ? 443 : 80;
            } catch (URISyntaxException ex) {
                throw new IllegalArgumentException("Invalid CALLBACK_PUBLIC_BASE_URL: " + callbackPublicBaseUrl, ex);
            }
        }
    }
}
