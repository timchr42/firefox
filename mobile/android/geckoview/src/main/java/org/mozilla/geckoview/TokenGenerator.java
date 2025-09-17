package org.mozilla.geckoview;

import android.util.Log;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.mozilla.gecko.util.GeckoBundle;
import org.mozilla.gecko.util.Token;
import org.mozilla.gecko.util.TokenPayload;

/**
 * Controls capability tokens for policy-based access control.
 * This implementation uses the Token structure with TokenPayload.
 */
public final class TokenGenerator {
    private static final String LOGTAG = "TokenGenerator";

    /**
     * Creates capability tokens based on the policy for a specific package.
     * Generates tokens organized by domain.
     *
     * @param policy The JSON policy object
     * @param packageName The package requesting capabilities
     * @param versionName The version of the package
     * @return A map of domain -> list of tokens for that domain
     */
    public static String generateCapabilityTokens(JSONObject policy, String packageName, String versionName) {
        Map<String, List<String>> tokensByDomain = new HashMap<>();

        try {
            // Process Entries with predefined cookie name
            if (policy.has("predefined")) {
                JSONObject predefined = policy.getJSONObject("predefined");

                // Process global predefined domains
                if (predefined.has("global")) {
                    JSONObject globalPredefined = predefined.getJSONObject("global");
                    processPredefined(globalPredefined, true, packageName, versionName, TokenPayload.AccessRights.READ, tokensByDomain);
                }

                // Process private predefined domains
                if (predefined.has("private")) {
                    JSONObject privatePredefined = predefined.getJSONObject("private");
                    processPredefined(privatePredefined, false, packageName, versionName, TokenPayload.AccessRights.READ, tokensByDomain);
                }
            }

            // Process wildcard domains
            if (policy.has("wildcard")) {
                JSONObject wildcard = policy.getJSONObject("wildcard");

                // Process global wildcard domains
                if (wildcard.has("global")) {
                    JSONArray globalWildcard = wildcard.getJSONArray("global");
                    processWildcard(globalWildcard, true, packageName, versionName, TokenPayload.AccessRights.READ, tokensByDomain);
                }

                // Process private wildcard domains
                if (wildcard.has("private")) {
                    JSONArray privateWildcard = wildcard.getJSONArray("private");
                    processWildcard(privateWildcard, false, packageName, versionName, TokenPayload.AccessRights.NONE, tokensByDomain);
                }
            }

            int totalTokens = tokensByDomain.values().stream().mapToInt(List::size).sum();
            Log.d(LOGTAG, "Generated " + totalTokens + " capability tokens across " + tokensByDomain.size() + " domains for " + packageName);

        } catch (Exception e) {
            Log.e(LOGTAG, "Failed to generate capability tokens for " + packageName, e);
        }

        logTokens(tokensByDomain, packageName);
        return tokensMapToJsonString(tokensByDomain);
    }

    /**
     * Process predefined domains where cookie names are specified
     */
    private static void processPredefined(JSONObject domains, boolean globalJar, String packageName, String versionName, TokenPayload.AccessRights rights, Map<String, List<String>> tokensByDomain) {
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
                    String token = generateSingleToken(domain, cookieName, "*", globalJar, packageName, versionName, rights);
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
    private static void processWildcard(JSONArray domains, boolean globalJar, String packageName, String versionName, TokenPayload.AccessRights rights, Map<String, List<String>> tokensByDomain) {
        try {
            for (int i = 0; i < domains.length(); i++) {
                String domain = domains.getString(i);

                // Ensure domain has a list in the map
                tokensByDomain.putIfAbsent(domain, new ArrayList<>());

                String token = generateSingleToken(domain, "*", "*", globalJar, packageName, versionName, rights);
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
    private static String generateSingleToken(String domain, String cookieName, String cookieValue,
                                     boolean globalJar, String packageName, String versionName, TokenPayload.AccessRights rights) {
        try {
            // Create token payload using the new TokenPayload structure
            TokenPayload payload = new TokenPayload(
                cookieName,
                cookieValue,
                packageName,
                versionName,
                domain,
                rights,
                globalJar
            );

            // Sign the token using the new Token class
            Token token = Token.sign(payload);

            // Encode to the compact wire format
            String encodedToken = token.encode();

            Log.d(LOGTAG, "Generated token for domain: " + domain + ", cookie: " + cookieName + ", globalJar: " + globalJar);

            return encodedToken;

        } catch (Exception e) {
            Log.e(LOGTAG, "Failed to generate token for domain: " + domain, e);
            return null;
        }
    }

    private static String tokensMapToJsonString(Map<String, List<String>> tokensByDomain) {
        try {
            JSONObject json = new JSONObject();
            for (Map.Entry<String, List<String>> entry : tokensByDomain.entrySet()) {
                String domain = entry.getKey();
                List<String> tokens = entry.getValue();
                JSONArray tokenArray = new JSONArray(tokens); // for (String token : tokens) { tokenArray.put(token); }
                json.put(domain, tokenArray);
            }
            return json.toString();
        } catch (Exception e) {
            Log.e(LOGTAG, "Failed to convert tokens map to JSON", e);
            return "";
        }
    }

    private static void logTokens(Map<String, List<String>> capabilityTokensByDomain, String packageName) {
        for (Map.Entry<String, List<String>> entry : capabilityTokensByDomain.entrySet()) {
            String domain = entry.getKey();
            List<String> tokens = entry.getValue();

            Log.d(LOGTAG, "Domain: " + domain + " has " + tokens.size() + " token(s)");

            for (int i = 0; i < tokens.size(); i++) {
                String token = tokens.get(i);
                String compressedToken = token.substring(0, Math.min(50, token.length()));
                Log.d(LOGTAG, "  Token " + (i + 1) + ": " + compressedToken + "...");
            }
        }
    }
}
