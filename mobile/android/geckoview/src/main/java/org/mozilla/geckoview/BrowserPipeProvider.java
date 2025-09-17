package org.mozilla.geckoview;

import android.app.PendingIntent;
import android.content.*;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.util.Log;
import android.content.pm.PackageManager;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Objects;

public class BrowserPipeProvider extends ContentProvider {
    private static final String LOGTAG = "BrowserPipeProvider";

    public static final String METHOD_GET_PIPE = "GET_PIPE";
    public static final String EXTRA_PIPE = "de.cispa.byetrack.EXTRA_PIPE";
    public static final int PI_FLAGS = android.app.PendingIntent.FLAG_ONE_SHOT | android.app.PendingIntent.FLAG_MUTABLE;

    @Override
    public Bundle call(String method, String arg, Bundle extras) {
        final Context ctx = getContext();
        if (ctx == null) return null;

        if (!METHOD_GET_PIPE.equals(method)) return null;

        // Only the Installer may request this pipe
        int callingUid = Binder.getCallingUid();
        if (!verifyCallerIsTrusted(callingUid)) {
            Log.w(LOGTAG, "Untrusted caller UID=" + callingUid);
        return null;
        }

        Intent base = new Intent().setComponent(new ComponentName(
            ctx.getPackageName(), "org.mozilla.geckoview.PolicyReceiver"));

        PendingIntent pipe = PendingIntent.getBroadcast(ctx, 0, base, PI_FLAGS);

        Bundle out = new Bundle();
        out.putParcelable(EXTRA_PIPE, pipe);
        return out;
    }

    private boolean verifyCallerIsTrusted(int uid) {
        PackageManager pm = getContext().getPackageManager();
        String packageName = pm.getNameForUid(uid);

        return Objects.equals(packageName, "de.cispa.custominstaller");
    }


    // Required but unused methods for ContentProvider
    @Override public boolean onCreate() { return true;}
    @Override public Cursor query(@NonNull Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) { return null; }
    @Nullable @Override public String getType(@NonNull Uri uri) { return null; }
    @Nullable @Override public Uri insert(@NonNull Uri uri, ContentValues values) { return null; }
    @Override public int delete(@NonNull Uri uri, String selection, String[] selectionArgs) { return 0; }
    @Override public int update(@NonNull Uri uri, ContentValues values, String selection, String[] selectionArgs) { return 0; }

}

