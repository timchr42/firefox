package org.mozilla.geckoview;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import org.json.JSONArray;
import org.json.JSONException;
import org.mozilla.gecko.util.Token;
import org.mozilla.gecko.util.TokenPayload;

public class TokenInfoProvider extends ContentProvider {
    private static final String LOGTAG = "TokenInfoProvider";

    @Override
    public Bundle call(@NonNull String method, String arg, Bundle extras) {
        Context context = getContext();
        int uid = Binder.getCallingUid();
        PackageManager pm = context.getPackageManager();
        String packageName = pm.getNameForUid(uid);

        if ("get_token_cookie_names".equals(method)) {
            Bundle tokensInfo = new Bundle();
            try {
                JSONArray tokensJson = new JSONArray(arg);

                for (int i = 0; i < tokensJson.length(); i++) {
                    String tokenStr = tokensJson.getString(i);
                    Token token = Token.decodeEncrypted(tokenStr);

                    if (!token.payload.applicationId.equals(packageName)) {
                        Log.w(LOGTAG, "[Byetrack] " + "token package Name: " + token.payload.applicationId + "; Binder uid: " + packageName);
                        tokensInfo.putString("value", "Token of another app");
                        return tokensInfo;
                    }

                    tokensInfo.putString(tokenStr, token.payload.cookieName);
                    Log.d(LOGTAG, "[Byetrack] : " + tokenStr + " -> " + token.payload.cookieName);
                }
            } catch (JSONException e) {
                // Log.e(LOGTAG, "Error parsing tokens array JSON", e);
                tokensInfo.putString("value", "Error parsing tokens array JSON");
                return tokensInfo;
            }

            return tokensInfo;
        }

        if ("get_token_cookie_value".equals(method)) {
            Bundle tokensInfo = new Bundle();
            Token token = Token.decodeEncrypted(arg);
            if (!token.payload.applicationId.equals(packageName)) {
                tokensInfo.putString("value", "Token of another app");
                Log.w(LOGTAG, "[Byetrack] " + "token package Name: " + token.payload.applicationId + "; Binder uid: " + packageName);
                return tokensInfo;
            }
            // check tokens permissions
            if (!token.payload.canRead()) {
                tokensInfo.putString("value", "No read permission");
                return tokensInfo;
            }

            tokensInfo.putString("value", token.payload.cookieValue);
            return tokensInfo;
        }

        if ("write_token_cookie_value".equals(method)) {
            Bundle writtenTokens = new Bundle();
            Token token = Token.decodeEncrypted(arg);
            if (!token.payload.applicationId.equals(packageName)) {
                writtenTokens.putString("updated_token", "Token of another app");
                Log.w(LOGTAG, "[Byetrack] " + "token package Name: " + token.payload.applicationId + "; Binder uid: " + packageName);
                return writtenTokens;
            }
            // check tokens permissions
            if (!token.payload.canWrite()) {
                writtenTokens.putString("updated_token", "No write permission");
                return writtenTokens; // No write permission
            }

            // Update token value - need to create new TokenPayload since fields are final
            String value = extras.getString("value");
            token.payload.setCookieValue(value);
            Token updatedToken = Token.sign(token.payload);
            String updatedTokenStr = updatedToken.encodeEncrypted();
            writtenTokens.putString("updated_token", updatedTokenStr);
            writtenTokens.putString("domain", token.payload.destinationDomain);
            return writtenTokens;
        }

        return null;
    }

    @Override public boolean onCreate() { return true;}
    @Override public Cursor query(@NonNull Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) { return null; }
    @Nullable @Override public String getType(@NonNull Uri uri) { return null; }
    @Override public int delete(@NonNull Uri uri, String selection, String[] selectionArgs) { return 0; }
    @Override public int update(@NonNull Uri uri, ContentValues values, String selection, String[] selectionArgs) { return 0; }
    @Override public Uri insert(@NonNull Uri uri, ContentValues values) { return null; }
}
