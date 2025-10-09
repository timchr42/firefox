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

    public static boolean isAmbient = false;

    public static String generateAmbientToken(String packageName, String versionName) {
        isAmbient = true;
        Log.w(LOGTAG, "No policy provided for " + packageName + "; Returning Ambient Wildcard token");
        String ambientToken = generateSingleToken("*", "*", "*", true, packageName, versionName, TokenPayload.AccessRights.READ);
        try {
            JSONObject json = new JSONObject();
            JSONArray tokenArray = new JSONArray();
            tokenArray.put(ambientToken);
            json.put("*", tokenArray);
            return json.toString();
        } catch (Exception e) {
            Log.e(LOGTAG, "Failed to create JSON for Ambient token", e);
            return "";
        }
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
    public static String generateCapabilityTokens(JSONObject policy, String packageName, String versionName) {
        Map<String, List<String>> tokensByDomain = new HashMap<>();

        try {
            // Collect all policy data
            Map<String, List<String>> globalCookies = collectCookies(policy, "global");
            Map<String, List<String>> privateCookies = collectCookies(policy, "private");
            List<String> globalWildcards = collectWildcards(policy, "global");
            List<String> privateWildcards = collectWildcards(policy, "private");

            // === STEP 2: Domain-level predefined conflicts ===
            for (Iterator<String> it = globalCookies.keySet().iterator(); it.hasNext();) {
                String domain = it.next();
                if (privateCookies.containsKey(domain)) {
                    Log.w(LOGTAG, "Conflict: domain '" + domain +
                            "' appears in both predefined GLOBAL and PRIVATE. Downgrading entire domain to PRIVATE.");
                    it.remove();
                }
            }

            // Cookie-level conflicts (same domain, same cookie)
            for (Map.Entry<String, List<String>> entry : privateCookies.entrySet()) {
                String domain = entry.getKey();
                List<String> privateCookieNames = entry.getValue();

                if (globalCookies.containsKey(domain)) {
                    List<String> globalCookieNames = globalCookies.get(domain);
                    Iterator<String> iter = globalCookieNames.iterator();
                    while (iter.hasNext()) {
                        String cookie = iter.next();
                        if (privateCookieNames.contains(cookie)) {
                            Log.w(LOGTAG, "Cookie-level conflict: '" + cookie + "' for domain '" + domain +
                                    "' exists in both GLOBAL and PRIVATE predefined. Using PRIVATE version only.");
                            iter.remove(); // remove from global side
                        }
                    }
                }
            }

            // Wildcard conflicts (same domain appears both global/private)
            for (Iterator<String> it = globalWildcards.iterator(); it.hasNext();) {
                String domain = it.next();
                if (privateWildcards.contains(domain)) {
                    Log.w(LOGTAG, "Wildcard conflict: domain '" + domain +
                            "' appears as wildcard in both GLOBAL and PRIVATE. Downgrading to PRIVATE.");
                    it.remove();
                }
            }

            // Cross-type conflicts (predefined <-> wildcard)
            // Predefined and wildcard sections are independent → no downgrades needed
            // Just keep both sets as-is.
            // This allows:
            //   - global predefined + private wildcard
            //   - global wildcard + private predefined
            //   without restriction

            // Token generation
            processPredefinedMap(globalCookies, true, packageName, versionName,
                    TokenPayload.AccessRights.READ, tokensByDomain);
            processPredefinedMap(privateCookies, false, packageName, versionName,
                    TokenPayload.AccessRights.READ, tokensByDomain);
            processWildcardList(globalWildcards, true, packageName, versionName,
                    TokenPayload.AccessRights.READ, tokensByDomain);
            processWildcardList(privateWildcards, false, packageName, versionName,
                    TokenPayload.AccessRights.NONE, tokensByDomain);

            int totalTokens = tokensByDomain.values().stream().mapToInt(List::size).sum();
            Log.d(LOGTAG, "Generated " + totalTokens + " capability tokens across "
                    + tokensByDomain.size() + " domains for " + packageName);

        } catch (Exception e) {
            Log.e(LOGTAG, "Failed to generate capability tokens for " + packageName, e);
        }

        logTokens(tokensByDomain, packageName);
        return tokensMapToJsonString(tokensByDomain);
    }


    private static Map<String, List<String>> collectCookies(JSONObject policy, String level) {
        Map<String, List<String>> map = new HashMap<>();
        try {
            if (!policy.has("predefined")) return map;
            JSONObject predefined = policy.getJSONObject("predefined");
            if (!predefined.has(level)) return map;
            JSONObject entries = predefined.getJSONObject(level);
            Iterator<String> it = entries.keys();
            while (it.hasNext()) {
                String domain = it.next();
                JSONArray cookies = entries.getJSONArray(domain);
                List<String> names = new ArrayList<>();
                for (int i = 0; i < cookies.length(); i++) {
                    names.add(cookies.getString(i));
                }
                map.put(domain, names);
            }
        } catch (Exception e) {
            Log.e(LOGTAG, "collectCookies error", e);
        }
        return map;
    }

    private static List<String> collectWildcards(JSONObject policy, String level) {
        List<String> list = new ArrayList<>();
        try {
            if (!policy.has("wildcard")) return list;
            JSONObject wildcard = policy.getJSONObject("wildcard");
            if (!wildcard.has(level)) return list;
            JSONArray arr = wildcard.getJSONArray(level);
            for (int i = 0; i < arr.length(); i++) list.add(arr.getString(i));
        } catch (Exception e) {
            Log.e(LOGTAG, "collectWildcards error", e);
        }
        return list;
    }

    // Convenience wrappers for existing generators:
    private static void processPredefinedMap(Map<String, List<String>> map, boolean globalJar,
                                            String pkg, String ver, TokenPayload.AccessRights rights,
                                            Map<String, List<String>> out) {
        for (Map.Entry<String, List<String>> e : map.entrySet()) {
            for (String cookie : e.getValue()) {
                String token = generateSingleToken(e.getKey(), cookie, "*", globalJar, pkg, ver, rights);
                if (token != null) out.computeIfAbsent(e.getKey(), k -> new ArrayList<>()).add(token);
            }
        }
    }

    private static void processWildcardList(List<String> domains, boolean globalJar,
                                            String pkg, String ver, TokenPayload.AccessRights rights,
                                            Map<String, List<String>> out) {
        for (String domain : domains) {
            String token = generateSingleToken(domain, "*", "*", globalJar, pkg, ver, rights);
            if (token != null) out.computeIfAbsent(domain, k -> new ArrayList<>()).add(token);
        }
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

            // Sign token
            Token token = Token.sign(payload);
            // Encode and encrypt token
            String encryptedToken = token.encodeEncrypted();

            Log.d(LOGTAG, "Generated encrypted token for domain: " + domain + ", cookie: " + cookieName + ", globalJar: " + globalJar);

            return encryptedToken;

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
