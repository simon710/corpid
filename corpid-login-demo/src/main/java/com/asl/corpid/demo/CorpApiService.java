package com.asl.corpid.demo;

import com.asl.corpid.helper.CorpidException;
import com.asl.corpid.helper.CorpidHelper;
import com.asl.corpid.helper.model.CorpidTokenResponse;
import com.fasterxml.jackson.databind.JsonNode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Wraps the four CorpID corp-domain e-service APIs described in
 * "CorpID-API-Specifications-for-e-services-v1.0.4":
 *   - Form Filling            (EXT-006) /api/eservice/v1/formFilling/initiateRequest        [encrypted content]
 *   - Anon Form Filling       (EXT-007) /api/eservice/v1/formFilling/anonymous/initiateRequest [encrypted content]
 *   - Digital Signing         (EXT-009) /api/eservice/v1/signing/initiateRequest            [plain JSON]
 *   - Anon Digital Signing    (EXT-012) /api/eservice/v1/signing/anonymous/initiateRequest  [plain JSON]
 *
 * Signing supports 3 signTypes (§4.11 / §4.16):
 *   PERSONAL_SIGN     - personal signing via iAM Smart / remote signing only
 *   CORPID_SIGN       - company chop only
 *   INTEGRATED_SIGN   - personal + company chop
 *
 * For anon signing, HKICHash is mandatory: SHA-256 of the HKIC identifier
 * (no check digit, e.g. "A123456") then Base64-encoded (§4.16).
 */
public class CorpApiService {

    public enum SignType {
        PERSONAL_SIGN,
        CORPID_SIGN,
        INTEGRATED_SIGN
    }

    public record CorpApiResult(
            boolean ok,
            String api,
            String endpoint,
            String requestJson,
            String responseJson,
            String error
    ) {
        public JsonNode toJson() {
            var node = LoginService.newObjectNode();
            node.put("ok", ok);
            node.put("api", api);
            node.put("endpoint", endpoint);
            node.put("requestJson", requestJson);
            node.put("responseJson", responseJson == null ? "" : responseJson);
            node.put("error", error == null ? "" : error);
            return node;
        }
    }

    private final CorpidHelper helper;
    private final String corpidDomain;

    public CorpApiService(CorpidHelper helper, String corpidDomain) {
        this.helper = helper;
        this.corpidDomain = corpidDomain;
    }

    // ---- Form Filling (with service login) -------------------------------------------

    public CorpApiResult formFilling(
            CorpidTokenResponse token,
            String state,
            String source,
            String redirectUri,
            List<String> corpProfileFields,
            List<String> eCorpFields
    ) {
        if (token == null) {
            return fail("formFilling", "/api/eservice/v1/formFilling/initiateRequest",
                    "CorpID token not available (complete login + company select first)");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("businessID", newBusinessId());
        body.put("cAccessToken", token.accessToken());
        body.put("cOpenID", token.openId());
        body.put("source", source);
        body.put("redirectURI", redirectUri);
        body.put("state", state);
        body.put("formName", "CorpID Demo Form");
        body.put("corpProfileFields", defaultIfEmpty(corpProfileFields, List.of("corpName", "brNo")));
        body.put("eCorpFields", defaultIfEmpty(eCorpFields, List.of("corpNameEn", "brNo")));
        return call("formFilling", "/api/eservice/v1/formFilling/initiateRequest", body, true);
    }

    // ---- Anonymous Form Filling (without service login) ------------------------------

    public CorpApiResult anonFormFilling(
            String source,
            String redirectUri,
            List<String> corpProfileFields,
            List<String> eCorpFields
    ) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("businessID", newBusinessId());
        body.put("source", source);
        body.put("redirectURI", redirectUri);
        body.put("formName", "CorpID Demo Anon Form");
        body.put("corpProfileFields", defaultIfEmpty(corpProfileFields, List.of("corpName", "brNo")));
        body.put("eCorpFields", defaultIfEmpty(eCorpFields, List.of("corpNameEn", "brNo")));
        return call("anonFormFilling", "/api/eservice/v1/formFilling/anonymous/initiateRequest", body, true);
    }

    // ---- Digital Signing (with service login) ----------------------------------------

    public CorpApiResult signing(
            CorpidTokenResponse token,
            String state,
            String source,
            String redirectUri,
            SignType signType,
            String documentName
    ) {
        if (token == null) {
            return fail("signing", "/api/eservice/v1/signing/initiateRequest",
                    "CorpID token not available (complete login + company select first)");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("businessID", newBusinessId());
        body.put("cAccessToken", token.accessToken());
        body.put("cOpenID", token.openId());
        body.put("signType", signType.name());
        body.put("requireAuthProof", false);
        body.put("hashCode", sampleDocHash());
        body.put("sigAlgo", "SHA256withRSA");
        body.put("source", source);
        body.put("redirectURI", redirectUri);
        body.put("state", state);
        body.put("serviceName", "CorpID Demo e-Service");
        body.put("documentName", documentName == null || documentName.isBlank() ? "Demo Document" : documentName);
        // Signing API request body is plain JSON (not CEK-encrypted) per §4.11.
        return call("signing", "/api/eservice/v1/signing/initiateRequest", body, false);
    }

    // ---- Anonymous Digital Signing (without service login) ---------------------------

    public CorpApiResult anonSigning(
            String source,
            String redirectUri,
            SignType signType,
            String hkic,
            String documentName
    ) {
        if (hkic == null || hkic.isBlank()) {
            return fail("anonSigning", "/api/eservice/v1/signing/anonymous/initiateRequest",
                    "HKIC is required for anonymous signing");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("businessID", newBusinessId());
        body.put("signType", signType.name());
        body.put("requireAuthProof", false);
        body.put("hashCode", sampleDocHash());
        body.put("sigAlgo", "SHA256withRSA");
        body.put("HKICHash", hkicHash(hkic));
        body.put("source", source);
        body.put("redirectURI", redirectUri);
        body.put("serviceName", "CorpID Demo e-Service");
        body.put("documentName", documentName == null || documentName.isBlank() ? "Demo Document" : documentName);
        // Anon signing API request body is plain JSON (not CEK-encrypted) per §4.16.
        return call("anonSigning", "/api/eservice/v1/signing/anonymous/initiateRequest", body, false);
    }

    // ---- Internals ----------------------------------------------------------------

    private CorpApiResult call(String api, String endpoint, Map<String, Object> body, boolean encryptContent) {
        String requestJson = LoginService.prettyJson(body);
        try {
            JsonNode root = helper.callCorpApi(endpoint, body, encryptContent);
            return new CorpApiResult(true, api, endpoint, requestJson,
                    LoginService.prettyJson(root), null);
        } catch (CorpidException ex) {
            return new CorpApiResult(false, api, endpoint, requestJson, null, ex.getMessage());
        } catch (Exception ex) {
            return new CorpApiResult(false, api, endpoint, requestJson, null,
                    ex.getClass().getSimpleName() + ": " + ex.getMessage());
        }
    }

    private CorpApiResult fail(String api, String endpoint, String reason) {
        return new CorpApiResult(false, api, endpoint, "", null, reason);
    }

    private static String newBusinessId() {
        // A UUID string (8-4-4-4-12 with dashes) is exactly 36 chars.
        return UUID.randomUUID().toString();
    }

    private static List<String> defaultIfEmpty(List<String> value, List<String> fallback) {
        return (value == null || value.isEmpty()) ? fallback : value;
    }

    /** SHA-256 of a demo document, Base64-encoded (stand-in for a real document hash). */
    private static String sampleDocHash() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest("CorpID demo signing document".getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }

    /**
     * HKICHash for anonymous signing: SHA-256 of the HKIC identifier (no check digit),
     * then Base64-encoded (§4.16). Example identifier "A123456".
     */
    public static String hkicHash(String hkic) {
        String identifier = hkic.trim().toUpperCase(java.util.Locale.ROOT).replaceAll("[^A-Z0-9]", "");
        // Strip trailing check digit if the identifier looks like HKID (1 letter + 6 digits + 1 check).
        if (identifier.length() == 8 && Character.isLetter(identifier.charAt(0))
                && identifier.substring(1, 7).chars().allMatch(Character::isDigit)
                && Character.isLetterOrDigit(identifier.charAt(7))) {
            identifier = identifier.substring(0, 7);
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(identifier.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }
}
