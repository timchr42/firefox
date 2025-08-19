package org.mozilla.geckoview;

import android.content.Context;
import android.content.Intent;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;
import java.util.List;
import java.util.Map;

public class PolicyManager {
    private static final String LOGTAG = "PolicyManager";
    private static final String ACTION = "org.mozilla.geckoview.POLICY_TRANSMISSION";

    private final Context mContext;
    private final TokenGenerator mTokenGenerator;

    public PolicyManager(Context context) {
        mContext = context.getApplicationContext();
        mTokenGenerator = new TokenGenerator();
        Log.i(LOGTAG, "PolicyManager initialized successfully with context: " + mContext.getClass().getSimpleName());
        // Note: Receiver registration is now handled statically via AndroidManifest.xml
        // No need to register dynamically anymore
    }

    /**
     * Constructor for use by the static BroadcastReceiver.
     * Does not register a dynamic receiver since the static one handles broadcasts.
     */
    public PolicyManager(Context context, boolean skipReceiverRegistration) {
        this(context);
        // This constructor is used by PolicyBroadcastReceiver to avoid double registration
    }


    /**
     * Create capabilities based on the received policy and forward them to the requesting app.
     * (Called by BroadcastReceiver)
     */
    public void createAndForwardCapabilities(JSONObject policy, String packageName, String versionNumber) {
        Log.d(LOGTAG, "Creating capabilities for " + packageName + " with policy: " + policy.toString());

        // Generate capability tokens using TokenGenerator (organized by domain)
        Map<String, List<String>> capabilityTokensByDomain = mTokenGenerator.generateCapabilityTokens(policy, packageName, versionNumber);

        if (!capabilityTokensByDomain.isEmpty()) {
            Log.d(LOGTAG, "Successfully generated tokens for " + capabilityTokensByDomain.size() + " domains for " + packageName);
            logTokens(capabilityTokensByDomain, packageName);

            // Send tokens back to the requesting app
            sendTokensToApp(capabilityTokensByDomain, packageName);

        } else {
            Log.e(LOGTAG, "Failed to generate capability tokens for " + packageName);
            // What to do if no tokens are generated?
        }
    }

    /**
     * Send capability tokens back to the requesting app via broadcast
     */
    private void sendTokensToApp(Map<String, List<String>> tokensByDomain, String packageName) {
        try {
            Intent responseIntent = new Intent("org.mozilla.geckoview.CAPABILITY_TOKENS")
                .addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES);
            responseIntent.setPackage(packageName); // Send only to requesting app

            // Convert tokens map to JSON for transmission
            JSONObject tokensJson = tokensMapToJson(tokensByDomain);

            responseIntent.putExtra("capability_tokens", tokensJson.toString());
            responseIntent.putExtra("timestamp", System.currentTimeMillis());

            Log.d(LOGTAG, "Sent capability tokens to " + packageName);
            mContext.sendBroadcast(responseIntent);

        } catch (Exception e) {
            Log.e(LOGTAG, "Failed to send tokens to " + packageName, e);
        }
    }

    private JSONObject tokensMapToJson(Map<String, List<String>> tokensByDomain) throws JSONException {
        JSONObject json = new JSONObject();
        for (Map.Entry<String, List<String>> entry : tokensByDomain.entrySet()) {
            String domain = entry.getKey();
            List<String> tokens = entry.getValue();
            JSONArray tokenArray = new JSONArray(tokens); // for (String token : tokens) { tokenArray.put(token); }
            json.put(domain, tokenArray);
        }
        return json;
    }

    private void logTokens(Map<String, List<String>> capabilityTokensByDomain, String packageName) {
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

