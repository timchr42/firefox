package org.mozilla.geckoview.callerid;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.util.Log;

import androidx.annotation.Nullable;

public class CallerIdProvider extends ContentProvider {
	private static final String LOGTAG = "CallerIdProvider";
	public static final String AUTH = "org.mozilla.geckoview.callerid";
	private static final String METHOD_GET_NONCE = "getNonce"; // method name for ContentResolver.call()
	private static final String OUT_NONCE = "nonce";

	@Override
	public boolean onCreate() {
		Log.d(LOGTAG, "CallerIdProvider created");
		return true;
	}

	@Nullable @Override
	public Bundle call(String method, @Nullable String arg, @Nullable Bundle extras) {
		Log.d(LOGTAG, "call() method: " + method + ", arg: " + arg);

		if (!METHOD_GET_NONCE.equals(method)) {
			Log.w(LOGTAG, "Unknown method: " + method);
			return null;
		}

		try {
			int uid = Binder.getCallingUid();
			PackageManager pm = getContext().getPackageManager();
			String packageName = pm.getNameForUid(uid);

			Log.d(LOGTAG, "Issuing nonce for purpose: " + arg + ", uid: " + uid + ", package: " + packageName);
			String nonce = CallerNonceStore.issue(arg, uid, packageName);

			Bundle out = new Bundle();
			out.putString(OUT_NONCE, nonce);
			return out;
		} catch (Exception e) {
			Log.e(LOGTAG, "Error generating nonce", e);
			return null;
		}
	}

	// Required but unused methods for ContentProvider
	@Nullable @Override public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) { return null; }
	@Nullable @Override public String getType(Uri uri) { return null; }
	@Nullable @Override public Uri insert(Uri uri, ContentValues values) { return null; }
	@Override public int delete(Uri uri, String selection, String[] selectionArgs) { return 0; }
	@Override public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) { return 0; }
}