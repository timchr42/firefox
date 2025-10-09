package org.mozilla.gecko.util;

import org.json.JSONException;
import org.json.JSONObject;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import android.util.Log;


// Token = payload + signature + encode/decode/verify

public final class Token {

    /**
     * JSON serialization and deserialization for TokenPayload.
     */
    final class Json {

        // Build a deterministically ordered JSON object for signing.
        static String sorted(TokenPayload p) {
            try {
                JSONObject o = new JSONObject();
                o.put("access_rights", p.accessRights.name());
                o.put("application_id", p.applicationId);
                o.put("cookie_name", p.cookieName);
                o.put("cookie_value", p.cookieValue);
                o.put("destination_domain", p.destinationDomain);
                o.put("version_name", p.versionName);
                o.put("global_jar", p.globalJar);
                return o.toString(); // keys inserted in fixed order above
            } catch (JSONException e) {
                throw new RuntimeException("Failed to serialize token payload", e);
            }
        }

        static TokenPayload parsePayload(String json) {
            try {
                JSONObject o = new JSONObject(json);
                return new TokenPayload(
                        o.getString("cookie_name"),
                        o.getString("cookie_value"),
                        o.getString("application_id"),
                        o.getString("version_name"),
                        o.getString("destination_domain"),
                        TokenPayload.AccessRights.valueOf(o.getString("access_rights")),
                        o.getBoolean("global_jar")
                );
            } catch (JSONException e) {
                throw new RuntimeException("Failed to parse token payload", e);
            }
        }
    }

    /**
     * Base64 URL encoding without padding.
     */
    final class B64 {

        static String urlNoPad(byte[] bytes) {
            return android.util.Base64.encodeToString(bytes,
                    android.util.Base64.URL_SAFE | android.util.Base64.NO_WRAP | android.util.Base64.NO_PADDING);
        }

        static byte[] urlNoPadDecode(String s) {
            return android.util.Base64.decode(s, android.util.Base64.URL_SAFE | android.util.Base64.NO_WRAP | android.util.Base64.NO_PADDING);
        }
    }

    /**
     * Cryptographic functions for token signing and verification.
     */
    final class Crypto {
        private static final String SECRET_KEY = "super-secret-key";
        private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
        private static final String KEY_ALGORITHM = "AES";

        static byte[] hmac(String alg, byte[] msg) {
            try {
                Mac mac = Mac.getInstance(alg);
                SecretKeySpec secretKeySpec = new SecretKeySpec(
                    SECRET_KEY.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA256"
                );
                mac.init(secretKeySpec);
                return mac.doFinal(msg);
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("HMAC failure", e);
            }
        }

        /**
         * Derives a 256-bit AES key from the secret key using SHA-256
         */
        private static SecretKey deriveAESKey() {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] keyBytes = digest.digest(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
                return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
            } catch (Exception e) {
                throw new RuntimeException("Key derivation failure", e);
            }
        }

        /**
         * Encrypts a token string using AES-CBC with a random IV
         * Returns: base64url(IV + encrypted_data)
         */
        static String encrypt(String plaintext) {
            try {
                SecretKey key = deriveAESKey();
                Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
                
                // Generate random IV
                byte[] iv = new byte[16]; // AES block size
                new SecureRandom().nextBytes(iv);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                
                cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
                byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
                
                // Combine IV + encrypted data
                byte[] combined = new byte[iv.length + encrypted.length];
                System.arraycopy(iv, 0, combined, 0, iv.length);
                System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
                
                return B64.urlNoPad(combined);
            } catch (Exception e) {
                throw new RuntimeException("Encryption failure", e);
            }
        }

        /**
         * Decrypts a token string encrypted with encrypt()
         * Input: base64url(IV + encrypted_data)
         * Returns: plaintext token
         */
        static String decrypt(String encryptedB64) {
            try {
                byte[] combined = B64.urlNoPadDecode(encryptedB64);
                
                if (combined.length < 16) {
                    throw new IllegalArgumentException("Invalid encrypted token length");
                }
                
                // Extract IV and encrypted data
                byte[] iv = new byte[16];
                byte[] encrypted = new byte[combined.length - 16];
                System.arraycopy(combined, 0, iv, 0, 16);
                System.arraycopy(combined, 16, encrypted, 0, encrypted.length);
                
                SecretKey key = deriveAESKey();
                Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
                byte[] decrypted = cipher.doFinal(encrypted);
                
                return new String(decrypted, StandardCharsets.UTF_8);
            } catch (Exception e) {
                throw new RuntimeException("Decryption failure", e);
            }
        }
    }

    private static final String HMAC_ALG = "HmacSHA256";

    public final TokenPayload payload;
    public final String signatureB64Url; // base64url(HMAC(payloadJson))

    public Token(TokenPayload payload, String signatureB64Url) {
        this.payload = payload;
        this.signatureB64Url = signatureB64Url;
    }

    // Compact wire format: base64url(JSON(payload)) + "." + signature
    public String encode() {
        String payloadJson = Json.sorted(payload);             // deterministic
        String payloadB64 = B64.urlNoPad(payloadJson.getBytes(StandardCharsets.UTF_8));
        return payloadB64 + "." + signatureB64Url;
    }

    // Encrypted wire format: AES-encrypted version of the encoded token
    public String encodeEncrypted() {
        String encoded = encode();
        return Crypto.encrypt(encoded);
    }

    public Token decodeDecrypted(String encodedEncrypted) {
        String decrypted = Crypto.decrypt(encodedEncrypted);
        return decode(decrypted);
    }

    public static Token sign(TokenPayload payload) {
        String payloadJson = Json.sorted(payload);
        byte[] mac = Crypto.hmac(HMAC_ALG, payloadJson.getBytes(StandardCharsets.UTF_8));
        String sig = B64.urlNoPad(mac);
        return new Token(payload, sig);
    }

    public static Token decode(String encoded) throws IllegalArgumentException {
        int dot = encoded.indexOf('.');
        if (dot <= 0 || dot == encoded.length() - 1) {
            throw new IllegalArgumentException("Malformed token");
        }
        String payloadB64 = encoded.substring(0, dot);
        String sig = encoded.substring(dot + 1);
        String payloadJson = new String(B64.urlNoPadDecode(payloadB64), StandardCharsets.UTF_8);
        TokenPayload payload = Json.parsePayload(payloadJson);
        return new Token(payload, sig);
    }

    public static Token decodeEncrypted(String encryptedToken) throws IllegalArgumentException {
        String encoded = Crypto.decrypt(encryptedToken);
        return decode(encoded);
    }

    public boolean verifySignature() {
        String payloadJson = Json.sorted(payload);
        byte[] expected = Crypto.hmac(HMAC_ALG, payloadJson.getBytes(StandardCharsets.UTF_8));
        byte[] got = B64.urlNoPadDecode(signatureB64Url);
        Log.d("Byetrack", "Verifying token signature. Expected: " + expected + "; Got: " + got);
        return java.util.Arrays.equals(expected, got);
    }

    public boolean verify(String expectedPackageName, String expectedVersionName, String expectedDomainName) {
        if (!payload.applicationId.equals(expectedPackageName)) {
            return false; // Package name mismatch
        }
        if (!payload.versionName.equals(expectedVersionName)) {
            return false; // Version name mismatch
        }
        if (!isValidDomainMatch(expectedDomainName, payload.destinationDomain)) {
            return false; // Domain name mismatch
        }
        return verifySignature(); // Verify the signature
    }
    /**
     *
     * Check if the expected domain matches the token's destination domain.
     * Supports wildcard domains (e.g., *.example.com matches sub.example.com)
     */
    private boolean isValidDomainMatch(String expectedDomain, String tokenDomain) {
        if (expectedDomain == null || tokenDomain == null) {
            return false;
        }

        // Exact match
        if (expectedDomain.equals(tokenDomain)) {
            return true;
        }

        // Wildcard match (token domain starts with *.)
        if (tokenDomain.startsWith("*.")) {
            String baseDomain = tokenDomain.substring(2); // Remove "*."
            return expectedDomain.endsWith("." + baseDomain) || expectedDomain.equals(baseDomain);
        }

        return false;
    }


}
