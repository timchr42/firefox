package org.mozilla.geckoview;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.util.Log;

import org.json.JSONObject;

public class PolicyManager {
    private static final String LOGTAG = "PolicyManager";
    private static final String ACTION = "org.mozilla.geckoview.POLICY_TRANSMISSION";

    private final Context mContext;
    private boolean mReceiverRegistered = false;

    public PolicyManager(Context context) {
        mContext = context.getApplicationContext();
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

            if (policyJson != null) {
                Log.d(LOGTAG, "Received policy from " + packageName + ": " + policyJson);
                try {
                    JSONObject policy = new JSONObject(policyJson);
                    createCapabilities(policy, packageName);
                } catch (Exception e) {
                    Log.e(LOGTAG, "Failed to parse policy JSON", e);
                }
            }
        }
    };

    private void createCapabilities(JSONObject policy, String packageName) {
        // Here you would:
        // - Validate policy
        // - Create capability tokens (JWT-style)
        // - Store them or pass them to native via JNI
        Log.d(LOGTAG, "Creating capabilities for " + packageName + " with policy: " + policy.toString());
    }
}

