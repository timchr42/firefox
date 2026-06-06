#include "ByetrackTokenEncoder.h"
#include "crypto/ByetrackCrypto.h"
#include "utils/ByetrackBase64Utils.h"
#include "core/ByetrackConstants.h"
//#include "js/JSON.h"
//#include "mozilla/dom/ScriptSettings.h"
//#include "xpcpublic.h"
//#include "nsJSUtils.h"
#include <string_view>

namespace mozilla::byetrack {

nsresult TokenEncoder::EncodeToken(const ByetrackToken& aToken,
                                  nsACString& aOutEncodedToken) {
  printf_stderr("Byetrack (Encoder) Encoding token for domain: %s\n",
                aToken.destinationDomain.BeginReading());

  // Convert token to JSON
  nsCString tokenJson;
  nsresult rv = TokenToJson(aToken, tokenJson);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Encoder) Failed to convert token to JSON\n");
    return rv;
  }

  printf_stderr("Byetrack (Encoder) Token JSON: %s\n", tokenJson.BeginReading());

  // Base64URL encode the JSON payload
  FallibleTArray<uint8_t> jsonBytes;
  if (!jsonBytes.AppendElements(reinterpret_cast<const uint8_t*>(tokenJson.BeginReading()),
                               tokenJson.Length(), fallible)) {
    return NS_ERROR_OUT_OF_MEMORY;
  }

  nsCString payloadB64;
  rv = Base64Utils::Encode(jsonBytes, payloadB64);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Encoder) Failed to base64 encode payload\n");
    return rv;
  }

  // Create HMAC signature
  FallibleTArray<uint8_t> signature;
  std::string_view payloadView(tokenJson.BeginReading(), tokenJson.Length());
  rv = hmac_sha256(payloadView, signature);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Encoder) Failed to create HMAC signature\n");
    return rv;
  }

  // Base64URL encode the signature
  nsCString signatureB64;
  rv = Base64Utils::Encode(signature, signatureB64);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Encoder) Failed to base64 encode signature\n");
    return rv;
  }

  // Combine: payload.signature
  aOutEncodedToken.Assign(payloadB64);
  aOutEncodedToken.Append(token::SEPARATOR);
  aOutEncodedToken.Append(signatureB64);

  printf_stderr("Byetrack (Encoder) Encoded token: %s\n", aOutEncodedToken.BeginReading());
  return NS_OK;
}

nsresult TokenEncoder::EncodeEncryptedToken(const ByetrackToken& aToken,
                                           nsACString& aOutEncryptedToken) {
  printf_stderr("Byetrack (Encoder) Encrypting token for domain: %s\n",
                aToken.destinationDomain.BeginReading());

  // First encode the token normally
  nsCString encodedToken;
  nsresult rv = EncodeToken(aToken, encodedToken);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Encoder) Failed to encode token\n");
    return rv;
  }

  // Encrypt the encoded token
  FallibleTArray<uint8_t> encryptedBytes;
  std::string_view tokenView(encodedToken.BeginReading(), encodedToken.Length());
  rv = aes_encrypt(tokenView, encryptedBytes);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Encoder) Failed to encrypt token\n");
    return rv;
  }

  // Base64URL encode the encrypted data
  rv = Base64Utils::Encode(encryptedBytes, aOutEncryptedToken);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Encoder) Failed to base64 encode encrypted token\n");
    return rv;
  }

  printf_stderr("Byetrack (Encoder) Successfully created encrypted token\n");
  return NS_OK;
}

nsresult TokenEncoder::DecodeTokenString(const nsACString& aEncodedToken,
                                        nsACString& aOutDecodedJson) {
  const int32_t dot = aEncodedToken.Find(token::SEPARATOR);
  if (dot <= 0 || dot == static_cast<int32_t>(aEncodedToken.Length()) - 1) {
    return NS_ERROR_INVALID_ARG;
  }

  // Split into payloadB64 and signature
  const nsDependentCSubstring payloadB64 = Substring(aEncodedToken, 0, dot);
  const nsDependentCSubstring signature = Substring(aEncodedToken, dot + 1);

  // Base64URL decode payload
  FallibleTArray<uint8_t> payloadBytes;
  nsresult rv = Base64Utils::Decode(payloadB64, payloadBytes);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Encoder) Failed to decode payload\n");
    return rv;
  }

  // Base64URL decode the provided signature
  FallibleTArray<uint8_t> signatureBytes;
  rv = Base64Utils::Decode(signature, signatureBytes);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Encoder) Failed to decode signature\n");
    return rv;
  }

  // Verify HMAC signature
  std::string_view payloadView(reinterpret_cast<const char*>(payloadBytes.Elements()),
                               payloadBytes.Length());

  // Calculate expected HMAC
  FallibleTArray<uint8_t> expectedHmac;
  rv = hmac_sha256(payloadView, expectedHmac);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Encoder) Failed to calculate HMAC\n");
    return rv;
  }

  if (!constantTimeEquals(expectedHmac, signatureBytes)) {
    printf_stderr("Byetrack (Encoder) HMAC signature verification failed\n");
    return NS_ERROR_INVALID_ARG;
  }

  // Convert bytes to string (UTF-8)
  if (!aOutDecodedJson.Assign(reinterpret_cast<const char*>(payloadBytes.Elements()),
                             payloadBytes.Length(), mozilla::fallible)) {
    printf_stderr("Byetrack (Encoder) Failed to convert bytes to string\n");
    return NS_ERROR_OUT_OF_MEMORY;
  }

  printf_stderr("Byetrack (Encoder) Successfully decoded token: %s\n", aOutDecodedJson.BeginReading());
  return NS_OK;
}

nsresult TokenEncoder::DecodeEncryptedTokenString(const nsACString& aEncryptedToken,
                                                 nsACString& aOutDecodedJson) {
  printf_stderr("Byetrack (Encoder) Decrypting token: %s\n", aEncryptedToken.BeginReading());

  // First, base64url decode the encrypted data
  FallibleTArray<uint8_t> encryptedBytes;
  nsresult rv = Base64Utils::Decode(aEncryptedToken, encryptedBytes);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Encoder) Failed to base64url decode encrypted token\n");
    return rv;
  }

  // Decrypt the data to get the original encoded token
  nsCString encodedToken;
  rv = aes_decrypt(encryptedBytes, encodedToken);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Encoder) Failed to decrypt token\n");
    return rv;
  }

  printf_stderr("Byetrack (Encoder) Decrypted to encoded token: %s\n", encodedToken.BeginReading());

  // Now decode the standard token
  return DecodeTokenString(encodedToken, aOutDecodedJson);
}

nsresult TokenEncoder::GetCookieHeader(const nsTArray<ByetrackToken>& aTokens,
                                      nsACString& aOutHeader) {
  if (aTokens.IsEmpty()) {
    aOutHeader.Truncate();
    return NS_OK;
  }

  printf_stderr("Byetrack (Encoder) Generating cookie header for %d tokens\n",
                (int)aTokens.Length());

  aOutHeader.Truncate();

  for (uint32_t i = 0; i < aTokens.Length(); i++) {
    const ByetrackToken& token = aTokens[i];

    if (i > 0) {
      aOutHeader.AppendLiteral("; ");
    }

    aOutHeader.Append(token.cookieName);
    aOutHeader.AppendLiteral("=");
    aOutHeader.Append(token.cookieValue);
  }

  printf_stderr("Byetrack (Encoder) Generated cookie header: %s\n", aOutHeader.BeginReading());
  return NS_OK;
}

nsresult TokenEncoder::TokenToJson(const ByetrackToken& aToken, nsACString& aOutJson) {
  aOutJson.Truncate();
  aOutJson.AppendLiteral("{");
  aOutJson.AppendLiteral("\"access_rights\":\"");
  aOutJson.Append(nsDependentCString(AccessRightsToString(aToken.accessRights)));
  aOutJson.AppendLiteral("\",\"application_id\":\"");
  aOutJson.Append(aToken.packageName);
  aOutJson.AppendLiteral("\",\"cookie_name\":\"");
  aOutJson.Append(aToken.cookieName);
  aOutJson.AppendLiteral("\",\"cookie_value\":\"");
  aOutJson.Append(aToken.cookieValue);
  aOutJson.AppendLiteral("\",\"destination_domain\":\"");
  aOutJson.Append(aToken.destinationDomain);
  aOutJson.AppendLiteral("\",\"version_name\":\"");
  aOutJson.Append(aToken.versionName);
  aOutJson.AppendLiteral("\",\"global_jar\":");
  if (aToken.globalJar) {
    aOutJson.AppendLiteral("true");
  } else {
    aOutJson.AppendLiteral("false");
  }
  aOutJson.AppendLiteral("}");
  return NS_OK;
}

//nsresult TokenEncoder::TokenToJson(const ByetrackToken& aToken,
//                                  nsACString& aOutJson) {
//  // Get JS context for JSON creation
//  dom::AutoJSAPI jsapi;
//  if (!jsapi.Init(xpc::PrivilegedJunkScope())) {
//    return NS_ERROR_FAILURE;
//  }
//  JSContext* cx = jsapi.cx();
//
//  // Create JSON object with deterministic field ordering (for consistent signatures)
//  JS::Rooted<JSObject*> obj(cx, JS_NewPlainObject(cx));
//  if (!obj) {
//    return NS_ERROR_FAILURE;
//  }
//
//  // Helper to set string property
//  auto setStringProp = [&](const char* name, const nsACString& value) -> bool {
//    NS_ConvertUTF8toUTF16 utf16Value(value);
//    JS::Rooted<JSString*> jsStr(cx, JS_NewUCStringCopyZ(cx, utf16Value.BeginReading()));
//    if (!jsStr) return false;
//    JS::Rooted<JS::Value> jsVal(cx, JS::StringValue(jsStr));
//    return JS_SetProperty(cx, obj, name, jsVal);
//  };
//
//  // Set properties in alphabetical order for consistency
//  if (!setStringProp(json::ACCESS_RIGHTS, nsDependentCString(AccessRightsToString(aToken.accessRights))) ||
//      !setStringProp(json::APPLICATION_ID, aToken.packageName) ||
//      !setStringProp(json::COOKIE_NAME, aToken.cookieName) ||
//      !setStringProp(json::COOKIE_VALUE, aToken.cookieValue) ||
//      !setStringProp(json::DESTINATION_DOMAIN, aToken.destinationDomain) ||
//      !setStringProp(json::VERSION_NAME, aToken.versionName)) {
//    return NS_ERROR_FAILURE;
//  }
//
//  // Set boolean property
//  JS::Rooted<JS::Value> globalJarVal(cx, JS::BooleanValue(aToken.globalJar));
//  if (!JS_SetProperty(cx, obj, json::GLOBAL_JAR, globalJarVal)) {
//    return NS_ERROR_FAILURE;
//  }
//
//  // Convert to JSON string using a different approach
//  JS::Rooted<JS::Value> objVal(cx, JS::ObjectValue(*obj));
//
//  // Use a string buffer to collect the JSON output
//  nsTArray<char16_t> buffer;
//
//  // Define a proper callback function that matches JSONWriteCallback signature
//  auto writeCallback = [](const char16_t* buf, uint32_t len, void* data) -> bool {
//    nsTArray<char16_t>* buffer = static_cast<nsTArray<char16_t>*>(data);
//    return buffer->AppendElements(buf, len, fallible);
//  };
//
//  if (!JS_Stringify(cx, &objVal, nullptr, JS::NullHandleValue, writeCallback, &buffer)) {
//    return NS_ERROR_FAILURE;
//  }
//
//  // Convert buffer to string
//  nsString jsonString(buffer.Elements(), buffer.Length());
//  aOutJson = NS_ConvertUTF16toUTF8(jsonString);
//  return NS_OK;
//}

} // namespace mozilla::byetrack
