package org.mozilla.geckoview;

import android.app.PendingIntent;
import android.content.Context;
import android.util.Log;
import androidx.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;

/**
 * Stores app channels (PendingIntents) for communication with apps.
 * This class is used to keep track of the communication channels
 * established with different apps based on their package names.
 */
public final class AppChannelStore {
    private static final String LOGTAG = "AppChannelStore";
    private static final Map<String, PendingIntent> appChannels = new HashMap<>();

    public static void storeAppChannel(String packageName, PendingIntent channel) {
        synchronized (appChannels) {
            appChannels.put(packageName, channel);
        }
        Log.d(LOGTAG, "Stored app channel for " + packageName);
    }

    @Nullable
    public static PendingIntent getAppChannel(String packageName) {
        PendingIntent channel;
        synchronized (appChannels) {
            channel = appChannels.get(packageName);
        }
        Log.d(LOGTAG, "Retrieved app channel for " + packageName + ": " + (channel != null ? "found" : "not found"));
        return channel;
    }
}
