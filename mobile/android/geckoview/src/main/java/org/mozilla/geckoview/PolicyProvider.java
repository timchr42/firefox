package org.mozilla.geckoview;

import android.content.Context;
import android.content.ContentProvider;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.util.Log;
import org.json.JSONObject;
import org.mozilla.gecko.GeckoAppShell;
import android.content.ContentValues;
import android.net.Uri;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import android.os.Binder;
import android.database.Cursor;
import android.os.Bundle;

import java.util.Objects;

public class PolicyProvider extends ContentProvider {
    private static final String LOGTAG = "PolicyProvider";

    private static final String INSTALLER_PACKAGE = "de.cispa.custominstaller";

    @Override
    public Uri insert(@NonNull Uri uri, ContentValues values) {
        Context context = getContext();

        if (!verifyCallerIsTrusted(Binder.getCallingUid(), context)) {
            Log.w(LOGTAG, "Untrusted caller UID=" + Binder.getCallingUid());
            return null;
        }

        String policyJson = values.getAsString("policy_json");
        String packageName = values.getAsString("package_name");
        String versionName = values.getAsString("version_name");

        boolean isAmbient = policyJson == null;
        Log.d(LOGTAG, "Received policy from " + packageName + ": " + policyJson + "; Ambient Mode: " + isAmbient);

        try {
            String tokensJson;
            if (isAmbient) {
                tokensJson = TokenGenerator.generateAmbientToken(packageName, versionName);
            } else {
                JSONObject policy = new JSONObject(policyJson);
                tokensJson = TokenGenerator.generateCapabilityTokens(policy, packageName, versionName);
            }

            // Call apps TokenProvider here to send tokens
            String AUTH = "content://" + packageName + ".tokens";

            ContentValues ValuesForApp = new ContentValues();
            ValuesForApp.put("capability_tokens", tokensJson);
            ValuesForApp.put("is_ambient", isAmbient);

            Log.d(LOGTAG, "[Byetrack] Sending tokens to " + packageName + " : " + tokensJson);
            context.getContentResolver().insert(Uri.parse(AUTH), ValuesForApp);

        } catch (Exception e) {
            Log.e(LOGTAG, "[Byetrack] Failed to send tokens", e);
        }

        return null;
    }

    private boolean verifyCallerIsTrusted(int uid, Context context) {
        PackageManager pm = context.getPackageManager();
        String packageName = pm.getNameForUid(uid);

        return Objects.equals(packageName, INSTALLER_PACKAGE);
    }

    // Required but unused methods for ContentProvider
    @Override public boolean onCreate() { return true;}
    @Override public Cursor query(@NonNull Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) { return null; }
    @Nullable @Override public String getType(@NonNull Uri uri) { return null; }
    @Override public int delete(@NonNull Uri uri, String selection, String[] selectionArgs) { return 0; }
    @Override public int update(@NonNull Uri uri, ContentValues values, String selection, String[] selectionArgs) { return 0; }
    @Override public Bundle call(@NonNull String method, String arg, Bundle extras) { return null;}
}
