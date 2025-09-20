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
        String versionName = intent.getStringExtra("version_name");

        PendingIntent appPipe = intent.getParcelableExtra("app_pipe", PendingIntent.class);
        PendingIntent appChannel = intent.getParcelableExtra("app_channel", PendingIntent.class);
        AppChannelStore.storeAppChannel(packageName, appChannel);

        Log.d(LOGTAG, "Received policy from " + packageName + ": " + policyJson);
        boolean isAmbient = policyJson == null;
        Log.d(LOGTAG, "isAmbient: " + isAmbient);

        try {
            String tokensJson;
            if (isAmbient) {
                tokensJson = TokenGenerator.generateAmbientToken(packageName, versionName);
            } else {
                JSONObject policy = new JSONObject(policyJson);
                tokensJson = TokenGenerator.generateCapabilityTokens(policy, packageName, versionName);
            }

            Intent fill = new Intent()
                .putExtra("capability_tokens", tokensJson)
                .putExtra("is_ambient", isAmbient);
            appPipe.send(context, 0, fill);

        } catch (Exception e) {
            Log.e(LOGTAG, "Sending tokens failed", e);
        }
    }

}
