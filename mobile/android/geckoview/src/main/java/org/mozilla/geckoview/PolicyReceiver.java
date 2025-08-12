package org.mozilla.geckoview;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import org.json.JSONObject;

/**
 * Standalone BroadcastReceiver for handling policy transmissions.
 * This receiver is registered statically in AndroidManifest.xml to ensure
 * it can receive broadcasts even when the browser is not running.
 */
public class PolicyReceiver extends BroadcastReceiver {
    private static final String LOGTAG = "PolicyReceiver";

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.d(LOGTAG, "Received policy intent: " + intent.getAction());

        String packageName = intent.getStringExtra("package_name");
        String policyJson = intent.getStringExtra("policy_json");
        String versionNumber = intent.getStringExtra("version_number");

        if (policyJson != null) {
            Log.d(LOGTAG, "Received policy from " + packageName + ": " + policyJson);
            try {
                JSONObject policy = new JSONObject(policyJson);
                // Create PolicyManager instance without registering dynamic receiver
                PolicyManager policyManager = new PolicyManager(context, true);
                policyManager.createAndForwardCapabilities(policy, packageName, versionNumber);
            } catch (Exception e) {
                Log.e(LOGTAG, "Failed to parse policy JSON", e);
            }
        } else {
            Log.w(LOGTAG, "Received policy intent without policy_json from " + packageName);
        }
    }
}
