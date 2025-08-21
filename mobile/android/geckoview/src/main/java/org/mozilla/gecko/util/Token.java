package org.mozilla.gecko.util;

import org.json.JSONException;
import org.json.JSONObject;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;


// Token = payload + signature + encode/decode/verify

public final class Token {

    /**
     * JSON serialization and deserialization for TokenPayload.
     */
    final class Json {

        // Build a deterministically ordered JSON object for signing.
        static String sorted(TokenPayload p) {
            try {
                JSONObject o = new JSONObject();
                o.put("access_rights", p.accessRights.name());
                o.put("application_id", p.applicationId);
                o.put("cookie_name", p.cookieName);
                o.put("cookie_value", p.cookieValue != null ? p.cookieValue : JSONObject.NULL);
                o.put("destination_domain", p.destinationDomain);
                o.put("global_jar", p.globalJar);
                o.put("version_name", p.versionName);
                return o.toString(); // keys inserted in fixed order above
            } catch (JSONException e) {
                throw new RuntimeException("Failed to serialize token payload", e);
            }
        }

        static TokenPayload parsePayload(String json) {
            try {
                JSONObject o = new JSONObject(json);
                return new TokenPayload(
                        o.getString("cookie_name"),
                        o.opt("cookie_value") == JSONObject.NULL ? null : o.getString("cookie_value"),
                        o.getString("application_id"),
                        o.getString("version_name"),
                        o.getString("destination_domain"),
                        TokenPayload.AccessRights.valueOf(o.getString("access_rights")),
                        o.getBoolean("global_jar")
                );
            } catch (JSONException e) {
                throw new RuntimeException("Failed to parse token payload", e);
            }
        }
    }

    /**
     * Base64 URL encoding without padding.
     */
    final class B64 {

        static String urlNoPad(byte[] bytes) {
            return android.util.Base64.encodeToString(bytes,
                    android.util.Base64.URL_SAFE | android.util.Base64.NO_WRAP | android.util.Base64.NO_PADDING);
        }

        static byte[] urlNoPadDecode(String s) {
            return android.util.Base64.decode(s, android.util.Base64.URL_SAFE | android.util.Base64.NO_WRAP | android.util.Base64.NO_PADDING);
        }
    }

    /**
     * Cryptographic functions for token signing and verification.
     */
    final class Crypto {
        private static final String SECRET_KEY = "super-secret-key";

        static byte[] hmac(String alg, byte[] msg) {
            try {
                Mac mac = Mac.getInstance(alg);
                SecretKeySpec secretKeySpec = new SecretKeySpec(
                    SECRET_KEY.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA256"
                );
                mac.init(secretKeySpec);
                return mac.doFinal(msg);
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("HMAC failure", e);
            }
        }
    }

    private static final String HMAC_ALG = "HmacSHA256";

    public final TokenPayload payload;
    public final String signatureB64Url; // base64url(HMAC(payloadJson))

    public Token(TokenPayload payload, String signatureB64Url) {
        this.payload = payload;
        this.signatureB64Url = signatureB64Url;
    }

    // Compact wire format: base64url(JSON(payload)) + "." + signature
    public String encode() {
        String payloadJson = Json.sorted(payload);             // deterministic
        String payloadB64 = B64.urlNoPad(payloadJson.getBytes(StandardCharsets.UTF_8));
        return payloadB64 + "." + signatureB64Url;
    }

    public static Token sign(TokenPayload payload) {
        String payloadJson = Json.sorted(payload);
        byte[] mac = Crypto.hmac(HMAC_ALG, payloadJson.getBytes(StandardCharsets.UTF_8));
        String sig = B64.urlNoPad(mac);
        return new Token(payload, sig);
    }

    public static Token decode(String encoded) throws IllegalArgumentException {
        int dot = encoded.indexOf('.');
        if (dot <= 0 || dot == encoded.length() - 1) {
            throw new IllegalArgumentException("Malformed token");
        }
        String payloadB64 = encoded.substring(0, dot);
        String sig = encoded.substring(dot + 1);
        String payloadJson = new String(B64.urlNoPadDecode(payloadB64), StandardCharsets.UTF_8);
        TokenPayload payload = Json.parsePayload(payloadJson);
        return new Token(payload, sig);
    }

    private boolean verifySignature() {
        String payloadJson = Json.sorted(payload);
        byte[] expected = Crypto.hmac(HMAC_ALG, payloadJson.getBytes(StandardCharsets.UTF_8));
        byte[] got = B64.urlNoPadDecode(signatureB64Url);
        return java.util.Arrays.equals(expected, got);
    }

    public boolean verify(String expectedPackageName, String expectedVersionName, String expectedDomainName) {
        if (!payload.applicationId.equals(expectedPackageName)) {
            return false; // Package name mismatch
        }
        if (!payload.versionName.equals(expectedVersionName)) {
            return false; // Version name mismatch
        }
        if (!isValidDomainMatch(expectedDomainName, payload.destinationDomain)/) {
            return false; // Domain name mismatch
        }
        return verifySignature(); // Verify the signature
    }
    /**
     *
     * Check if the expected domain matches the token's destination domain.
     * Supports wildcard domains (e.g., *.example.com matches sub.example.com)
     */
    private boolean isValidDomainMatch(String expectedDomain, String tokenDomain) {
        if (expectedDomain == null || tokenDomain == null) {
            return false;
        }

        // Exact match
        if (expectedDomain.equals(tokenDomain)) {
            return true;
        }

        // Wildcard match (token domain starts with *.)
        if (tokenDomain.startsWith("*.")) {
            String baseDomain = tokenDomain.substring(2); // Remove "*."
            return expectedDomain.endsWith("." + baseDomain) || expectedDomain.equals(baseDomain);
        }

        return false;
    }


}
