package org.mozilla.geckoview;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
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
    private boolean mReceiverRegistered = false;

    public PolicyManager(Context context) {
        mContext = context.getApplicationContext();
        mTokenGenerator = new TokenGenerator();
        Log.i(LOGTAG, "PolicyManager initialized successfully with context: " + mContext.getClass().getSimpleName());
        // Automatically register the receiver
        registerReceiver();
    }

    /**
     * Register the broadcast receiver to listen for policy transmissions.
     * This is called automatically during construction.
     */
    private void registerReceiver() {
        if (!mReceiverRegistered) {
            IntentFilter filter = new IntentFilter(ACTION);
            mContext.registerReceiver(policyReceiver, filter, Context.RECEIVER_EXPORTED);

            mReceiverRegistered = true;
            Log.d(LOGTAG, "PolicyReceiver registered for action: " + ACTION);
        }
    }

    /**
     * Unregister the broadcast receiver to prevent memory leaks.
     * Should be called when the PolicyManager is no longer needed.
     */
    public void shutdown() {
        if (mReceiverRegistered) {
            try {
                mContext.unregisterReceiver(policyReceiver);
                mReceiverRegistered = false;
                Log.d(LOGTAG, "PolicyReceiver unregistered");
            } catch (IllegalArgumentException e) {
                Log.w(LOGTAG, "PolicyReceiver was not registered", e);
            }
        }
    }

    private final BroadcastReceiver policyReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String packageName = intent.getStringExtra("package_name");
            String policyJson = intent.getStringExtra("policy_json");
            String versionNumber = intent.getStringExtra("version_number");

            if (policyJson != null) {
                Log.d(LOGTAG, "Received policy from " + packageName + ": " + policyJson);
                try {
                    JSONObject policy = new JSONObject(policyJson);
                    createCapabilities(policy, packageName, versionNumber);
                } catch (Exception e) {
                    Log.e(LOGTAG, "Failed to parse policy JSON", e);
                }
            }
        }
    };

    private void createCapabilities(JSONObject policy, String packageName, String versionNumber) {
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
        }
    }

    /**
     * Send capability tokens back to the requesting app via broadcast
     */
    private void sendTokensToApp(Map<String, List<String>> tokensByDomain, String packageName) {
        try {
            Intent responseIntent = new Intent("org.mozilla.geckoview.CAPABILITY_TOKENS");
            responseIntent.setPackage(packageName); // Send only to requesting app

            // Convert tokens map to JSON for transmission
            JSONObject tokensJson = tokensMapToJson(tokensByDomain);

            responseIntent.putExtra("capability_tokens", tokensJson.toString());
            responseIntent.putExtra("status", "success");
            responseIntent.putExtra("timestamp", System.currentTimeMillis());

            Log.d(LOGTAG, "Sent capability tokens to " + packageName);
            mContext.sendBroadcast(responseIntent);

        } catch (Exception e) {
            Log.e(LOGTAG, "Failed to send tokens to " + packageName, e);
            
            // Send error response
            Intent errorIntent = new Intent("org.mozilla.geckoview.CAPABILITY_TOKENS");
            errorIntent.setPackage(packageName);
            errorIntent.putExtra("status", "error");
            errorIntent.putExtra("error_message", e.getMessage());
            mContext.sendBroadcast(errorIntent);
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

