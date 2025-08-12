package org.mozilla.geckoview;

import android.util.Base64;
import android.util.Log;
import org.json.JSONArray;
import org.json.JSONObject;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Controls capability tokens for policy-based access control.
 * This is a proof-of-concept implementation using simple JWT-style tokens.
 */
public class TokenGenerator {
    private static final String LOGTAG = "TokenGenerator";

    // For POC - in production this should be:
    // 1. Loaded from secure storage
    // 2. Rotated periodically
    // 3. Different per app/session
    private static final String SECRET_KEY = "super-secret-key";

    private final SecureRandom secureRandom;

    public TokenGenerator() {
        secureRandom = new SecureRandom();
        Log.d(LOGTAG, "TokenGenerator initialized");
    }

    /**
     * Creates capability tokens based on the policy for a specific package.
     * Generates tokens organized by domain.
     *
     * @param policy The JSON policy object
     * @param packageName The package requesting capabilities
     * @param versionName The version of the package
     * @return A map of domain -> list of tokens for that domain
     */
    public Map<String, List<String>> generateCapabilityTokens(JSONObject policy, String packageName, String versionName) {
        Map<String, List<String>> tokensByDomain = new HashMap<>();

        try {
            // Process Entries with predefined cookie name
            if (policy.has("predefined")) {
                JSONObject predefined = policy.getJSONObject("predefined");

                // Process global predefined domains
                if (predefined.has("global")) {
                    JSONObject globalPredefined = predefined.getJSONObject("global");
                    processPredefined(globalPredefined, "global", packageName, versionName, "R", tokensByDomain);
                }

                // Process private predefined domains
                if (predefined.has("private")) {
                    JSONObject privatePredefined = predefined.getJSONObject("private");
                    processPredefined(privatePredefined, "private", packageName, versionName, "R", tokensByDomain);
                }
            }

            // Process wildcard domains
            if (policy.has("wildcard")) {
                JSONObject wildcard = policy.getJSONObject("wildcard");

                // Process global wildcard domains
                if (wildcard.has("global")) {
                    JSONArray globalWildcard = wildcard.getJSONArray("global");
                    processWildcard(globalWildcard, "global", packageName, versionName, "R", tokensByDomain);
                }

                // Process private wildcard domains
                if (wildcard.has("private")) {
                    JSONArray privateWildcard = wildcard.getJSONArray("private");
                    processWildcard(privateWildcard, "private", packageName, versionName, "", tokensByDomain);
                }
            }

            int totalTokens = tokensByDomain.values().stream().mapToInt(List::size).sum();
            Log.d(LOGTAG, "Generated " + totalTokens + " capability tokens across " + tokensByDomain.size() + " domains for " + packageName);

        } catch (Exception e) {
            Log.e(LOGTAG, "Failed to generate capability tokens for " + packageName, e);
        }

        return tokensByDomain;
    }

    /**
     * Process predefined domains where cookie names are specified
     */
    private void processPredefined(JSONObject domains, String jarType, String packageName, String versionName, String rights, Map<String, List<String>> tokensByDomain) {
        try {
            Iterator<String> domainKeys = domains.keys();
            while (domainKeys.hasNext()) {
                String domain = domainKeys.next();
                JSONArray cookieNames = domains.getJSONArray(domain);

                // Ensure domain has a list in the map
                tokensByDomain.putIfAbsent(domain, new ArrayList<>());

                // Generate one token per cookie name for this domain
                for (int i = 0; i < cookieNames.length(); i++) {
                    String cookieName = cookieNames.getString(i);
                    String token = generateSingleToken(domain, cookieName, null, jarType, packageName, versionName, rights);
                    if (token != null) {
                        tokensByDomain.get(domain).add(token);
                    }
                }
            }
        } catch (Exception e) {
            Log.e(LOGTAG, "Error processing predefined domains", e);
        }
    }

    /**
     * Process wildcard domains where cookie names are wildcards
     */
    private void processWildcard(JSONArray domains, String jarType, String packageName, String versionName, String rights, Map<String, List<String>> tokensByDomain) {
        try {
            for (int i = 0; i < domains.length(); i++) {
                String domain = domains.getString(i);

                // Ensure domain has a list in the map
                tokensByDomain.putIfAbsent(domain, new ArrayList<>());

                String token = generateSingleToken(domain, "wildcard", "wildcard", jarType, packageName, versionName, rights);
                if (token != null) {
                    tokensByDomain.get(domain).add(token);
                }
            }
        } catch (Exception e) {
            Log.e(LOGTAG, "Error processing wildcard domains", e);
        }
    }

    /**
     * Generate a single capability token for a specific domain and cookie
     */
    private String generateSingleToken(String domain, String cookieName, String cookieValue,
                                     String jarType, String packageName, String versionName, String rights) {
        try {
            // Create token payload
            JSONObject tokenPayload = new JSONObject();
            tokenPayload.put("cookie_name", cookieName);
            tokenPayload.put("cookie_value", cookieValue != null ? cookieValue : "wildcard");
            tokenPayload.put("application_id", packageName);
            tokenPayload.put("version_name", versionName);
            tokenPayload.put("destination_domain", domain);
            tokenPayload.put("access_rights", rights);
            tokenPayload.put("global_jar", jarType);

            tokenPayload.put("timestamp", System.currentTimeMillis());
            tokenPayload.put("nonce", generateNonce());

            // For POC: Simple base64 encoding with basic signature
            String payload = tokenPayload.toString();
            String signature = createSimpleSignature(payload);

            JSONObject token = new JSONObject();
            token.put("payload", payload);
            token.put("signature", signature);

            String tokenString = token.toString();
            String encodedToken = Base64.encodeToString(
                tokenString.getBytes(StandardCharsets.UTF_8),
                Base64.NO_WRAP
            );

            Log.d(LOGTAG, "Generated token for domain: " + domain + ", cookie: " + cookieName + ", jar: " + jarType);

            return encodedToken;

        } catch (Exception e) {
            Log.e(LOGTAG, "Failed to generate token for domain: " + domain, e);
            return null;
        }
    }

    /**
     * Validates a capability token (for future use)
     */
    public boolean isTokenValid(String encodedToken, String expectedDomain, String expectedVersionName, String expectedPackageName) {
        try {
            String tokenString = new String(
                Base64.decode(encodedToken, Base64.NO_WRAP),
                StandardCharsets.UTF_8
            );

            JSONObject token = new JSONObject(tokenString);
            String payload = token.getString("payload");
            String signature = token.getString("signature");

            // Verify signature
            String expectedSignature = createSimpleSignature(payload);
            boolean isValid = expectedSignature.equals(signature);

            if (!isValid) {
                return false;
            }

            // Signature valid => Check other properties (app version, domain, appid(packageName))
            JSONObject payloadObj = new JSONObject(payload);
            String version_name = payloadObj.getString("version_name");
            String destination_domain = payloadObj.getString("destination_domain");
            String app_id = payloadObj.getString("application_id");

            if (!expectedVersionName.equals(version_name) ||
                (!expectedDomain.equals(destination_domain) || (destination_domain.startsWith("*.") && expectedDomain.endsWith(destination_domain.substring(2)))) ||
                !expectedPackageName.equals(app_id)) {

                Log.e(LOGTAG, "Token validation failed - Version: " + version_name + ", Domain: " + destination_domain + ", App ID: " + app_id);
                return false;
            }
            return true;

        } catch (Exception e) {
            Log.e(LOGTAG, "Token validation process failed", e);
            return false;
        }
    }


    /**
     * Validate tokens for a specific domain (public method)
     */
    public JSONArray getValidTokens(JSONArray encodedTokens, String expectedDomain, String expectedVersionName, String expectedPackageName) {
        JSONArray validTokens = new JSONArray();

        try {
            for (int i = 0; i < encodedTokens.length(); i++) {
                String encodedToken = encodedTokens.getString(i);

                if (isTokenValid(encodedToken, expectedDomain, expectedVersionName, expectedPackageName)) {
                    Log.d(LOGTAG, "Token " + (i + 1) + " is valid");
                    validTokens.put(encodedToken);
                }
                // else: ignore? future maybe notify app of invalid token?
            }

            return validTokens;

        } catch (Exception e) {
            Log.e(LOGTAG, "Error validating tokens", e);
            return validTokens;
        }
    }

    private String generateNonce() {
        byte[] nonce = new byte[16];
        secureRandom.nextBytes(nonce);
        return Base64.encodeToString(nonce, Base64.NO_WRAP);
    }

    private String createSimpleSignature(String payload) {
        // POC signature (instead of HMAC-SHA256 for example)
        String combined = payload + SECRET_KEY;
        return String.valueOf(combined.hashCode());
    }


    /**
     * Extract cookie information from validated tokens.
     * Returns a map of cookie_name -> cookie_value for all valid tokens.
     *
     * @param validTokens JSONArray of validated tokens
     * @return Map containing cookie name-value pairs
     */
    public Map<String, String> extractCookiesFromTokens(JSONArray validTokens) {
        Map<String, String> cookies = new HashMap<>();

        try {
            for (int i = 0; i < validTokens.length(); i++) {
                String encodedToken = validTokens.getString(i);
                
                // Decode the token
                String tokenString = new String(
                    Base64.decode(encodedToken, Base64.NO_WRAP),
                    StandardCharsets.UTF_8
                );

                JSONObject token = new JSONObject(tokenString);
                String payload = token.getString("payload");
                
                // Parse the payload to extract cookie information
                JSONObject payloadObj = new JSONObject(payload);
                String cookieName = payloadObj.getString("cookie_name");
                String cookieValue = payloadObj.getString("cookie_value");
                
                // Skip wildcard cookies as they don't have specific values
                if (!cookieName.equals("wildcard") && !cookieValue.equals("wildcard")) {
                    cookies.put(cookieName, cookieValue);
                    Log.d(LOGTAG, "Extracted cookie: " + cookieName + " = " + cookieValue);
                } else {
                    Log.d(LOGTAG, "Skipping wildcard token for cookie extraction");
                }
            }

            Log.d(LOGTAG, "Extracted " + cookies.size() + " cookies from " + validTokens.length() + " valid tokens");

        } catch (Exception e) {
            Log.e(LOGTAG, "Error extracting cookies from tokens", e);
        }

        return cookies;
    }

}
