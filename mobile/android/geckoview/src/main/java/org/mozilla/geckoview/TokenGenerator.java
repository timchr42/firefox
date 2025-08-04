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
     * @param versionNumber The version of the package
     * @return A map of domain -> list of tokens for that domain
     */
    public Map<String, List<String>> generateCapabilityTokens(JSONObject policy, String packageName, String versionNumber) {
        Map<String, List<String>> tokensByDomain = new HashMap<>();
        
        try {
            // Process Entries with predefined cookie name
            if (policy.has("predefined")) {
                JSONObject predefined = policy.getJSONObject("predefined");
                
                // Process global predefined domains
                if (predefined.has("global")) {
                    JSONObject globalPredefined = predefined.getJSONObject("global");
                    processPredefined(globalPredefined, "global", packageName, versionNumber, "R", tokensByDomain);
                }

                // Process private predefined domains
                if (predefined.has("private")) {
                    JSONObject privatePredefined = predefined.getJSONObject("private");
                    processPredefined(privatePredefined, "private", packageName, versionNumber, "R", tokensByDomain);
                }
            }

            // Process wildcard domains
            if (policy.has("wildcard")) {
                JSONObject wildcard = policy.getJSONObject("wildcard");

                // Process global wildcard domains
                if (wildcard.has("global")) {
                    JSONArray globalWildcard = wildcard.getJSONArray("global");
                    processWildcard(globalWildcard, "global", packageName, versionNumber, "R", tokensByDomain);
                }

                // Process private wildcard domains
                if (wildcard.has("private")) {
                    JSONArray privateWildcard = wildcard.getJSONArray("private");
                    processWildcard(privateWildcard, "private", packageName, versionNumber, "", tokensByDomain);
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
    private void processPredefined(JSONObject domains, String jarType, String packageName, String versionNumber, String rights, Map<String, List<String>> tokensByDomain) {
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
                    String token = generateSingleToken(domain, cookieName, null, jarType, packageName, versionNumber, rights);
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
    private void processWildcard(JSONArray domains, String jarType, String packageName, String versionNumber, String rights, Map<String, List<String>> tokensByDomain) {
        try {
            for (int i = 0; i < domains.length(); i++) {
                String domain = domains.getString(i);

                // Ensure domain has a list in the map
                tokensByDomain.putIfAbsent(domain, new ArrayList<>());
                
                String token = generateSingleToken(domain, "wildcard", "wildcard", jarType, packageName, versionNumber, rights);
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
                                     String jarType, String packageName, String versionNumber, String rights) {
        try {
            // Create token payload
            JSONObject tokenPayload = new JSONObject();
            tokenPayload.put("cookie_name", cookieName);
            tokenPayload.put("cookie_value", cookieValue != null ? cookieValue : "wildcard");
            tokenPayload.put("application_id", packageName);
            tokenPayload.put("version_number", versionNumber);
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
    public boolean validateToken(String encodedToken) {
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

            if (isValid) {
                // Additional validation: check timestamp, nonce, etc.
                JSONObject payloadObj = new JSONObject(payload);
                long timestamp = payloadObj.getLong("timestamp");
                long currentTime = System.currentTimeMillis();

                // Token expires after 1 hour (for POC)
                boolean notExpired = (currentTime - timestamp) < (60 * 60 * 1000);

                return notExpired;
            }

            return false;

        } catch (Exception e) {
            Log.e(LOGTAG, "Token validation failed", e);
            return false;
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
}
