package org.mozilla.geckoview;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
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
        Log.i(LOGTAG, "PolicyReceiver onReceive " + intent);

        String policyJson = intent.getStringExtra("policy_json");
        String packageName = intent.getStringExtra("package_name");
        String versionNumber = getAppVersionName(packageName, context);

        PendingIntent appPipe = intent.getParcelableExtra("app_pipe", PendingIntent.class);

        if (policyJson == null) return; // TODO: Enable Ambient Mode
        Log.d(LOGTAG, "Received policy from " + packageName + ": " + policyJson);

        try {
            JSONObject policy = new JSONObject(policyJson);
            String tokensJson = TokenGenerator.generateCapabilityTokens(policy, packageName, versionNumber);

            Intent fill = new Intent().putExtra("capability_tokens", tokensJson);
            appPipe.send(context, 0, fill);
        } catch (Exception e) {
            Log.e(LOGTAG, "Sending tokens failed", e);
        }
    }

    private String getAppVersionName(String packageName, Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            PackageInfo info = pm.getPackageInfo(packageName, 0);
            return info.versionName;  // e.g., "1.0.3"
        } catch (PackageManager.NameNotFoundException e) {
            return null;
        }
    }


}
