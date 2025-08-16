package org.mozilla.geckoview_example.callerid;

import android.util.Base64;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class CallerNonceStore {
    private static final SecureRandom RNG = new SecureRandom();
    private static final long TTL_MS = 30_000; // 30s
    private static final Map<String, Record> CACHE = new ConcurrentHashMap<>();

    public static final class Record {
        public final int uid;
        public final String packageName;
        private final long expiresAt;

        Record(int uid, String pkg, long expiresAt) {
            this.uid = uid;
            this.packageName = pkg;
            this.expiresAt = expiresAt;
        }

        boolean expired() { 
            return System.currentTimeMillis() > expiresAt; 
        }
        
        @Override 
        public String toString() {
            return "uid=" + uid + " pkg=" + packageName;
        }
    }

    public static String issue(String purpose, int uid, String packageName) {
        String nonce = purpose + "." + randomToken();
        CACHE.put(nonce, new Record(uid, packageName, System.currentTimeMillis() + TTL_MS));
        return nonce;
    }

    public static Record consume(String nonce) {
        if (nonce == null) return null;
        Record rec = CACHE.remove(nonce);
        if (rec == null || rec.expired()) return null;
        return rec;
    }

    private static String randomToken() {
        byte[] b = new byte[24];
        RNG.nextBytes(b);
        return Base64.encodeToString(b, Base64.NO_WRAP);
    }
}
