#include "ByetrackCodec.h"
#include "ByetrackCrypto.h"
#include "js/Array.h"
#include "js/JSON.h"
#include "js/PropertyAndElement.h"
#include "xpcpublic.h"
#include "mozilla/dom/ScriptSettings.h"
#include "mozilla/Base64.h"
#include "nsJSUtils.h"
#include <string_view>

namespace mozilla::byetrack {

nsresult parseTokenBlob(const nsACString& aBlob, const nsACString& aDomainName,
                        const nsACString& aPackageName, const nsACString& aVersionName,
                        nsTArray<ByetrackToken>& outTokens) {

  if (aBlob.IsEmpty()) {
    printf_stderr("Byetrack (Codec) empty token blob => skip parsing\n");
    return NS_OK; // no tokens => no work to do
  }
  printf_stderr("Byetrack (Codec) parsing token blob: %s\n", aBlob.BeginReading());

  // Get JS context for parsing
  dom::AutoJSAPI jsapi;
  if (!jsapi.Init(xpc::PrivilegedJunkScope())) {
    return NS_ERROR_FAILURE;
  }
  JSContext* cx = jsapi.cx();

  // Parse JSON blob
  JS::Rooted<JS::Value> jsonValue(cx);
  if (!JS_ParseJSON(cx, NS_ConvertUTF8toUTF16(aBlob).BeginReading(),
                    aBlob.Length(), &jsonValue)) {
    return NS_ERROR_INVALID_ARG;
  }

  // Check if it's an array
  bool isArray;
  JS::Rooted<JSObject*> jsonArray(cx, &jsonValue.toObject());
  if (!JS::IsArrayObject(cx, jsonArray, &isArray) || !isArray) {
    return NS_ERROR_INVALID_ARG;
  }

  // Get array length
  uint32_t length;
  if (!JS::GetArrayLength(cx, jsonArray, &length)) {
    return NS_ERROR_FAILURE;
  }

  // Iterate over each entry in the array
  for (uint32_t i = 0; i < length; i++) {
    JS::Rooted<JS::Value> tokenValue(cx);
    if (!JS_GetElement(cx, jsonArray, i, &tokenValue)) {
      printf_stderr("Byetrack (Codec) failed to get element at index %d\n", i);
      return NS_ERROR_INVALID_ARG;
    }
    
    if (!tokenValue.isString()) {
      printf_stderr("Byetrack (Codec) element at index %d is not a string\n", i);
      return NS_ERROR_INVALID_ARG;
    }

    // Convert JS string to nsCString
    JSString* str = tokenValue.toString();
    nsAutoJSString autoStr;
    if (!autoStr.init(cx, str)) {
      printf_stderr("Byetrack (Codec) failed to convert string at index %d\n", i);
      return NS_ERROR_FAILURE;
    }
    
    nsCString encodedTokenStr = NS_ConvertUTF16toUTF8(autoStr);
    printf_stderr("Byetrack (Codec) encoded token at index %d: %s\n", i, encodedTokenStr.BeginReading());

    // decode encodedTokenStr
    nsCString decodedJsonString;
    nsresult decode_rv = decodeTokenString(encodedTokenStr, decodedJsonString);
    if (NS_FAILED(decode_rv)) {
      printf_stderr("Byetrack (Codec) decode Failed");
      return decode_rv;
    }
    printf_stderr("Byetrack (Codec) decoded JSON string: %s\n", decodedJsonString.BeginReading());

    ByetrackToken decodedToken;
    nsresult parse_rv = parseSingleToken(decodedJsonString, decodedToken);
    if (NS_FAILED(parse_rv)) {
      return parse_rv;
    }

    nsresult validate_rv = validateTokenFields(aPackageName, aVersionName, aDomainName, decodedToken);
    if (NS_FAILED(validate_rv)) {
      return validate_rv;
    }

    printf_stderr("Byetrack (Codec) wildcard token: %s\n", decodedToken.toString().BeginReading());
    outTokens.AppendElement(decodedToken);
  }
  return NS_OK;
}


nsresult parseSingleToken(const nsACString& decodedJsonString, ByetrackToken& outToken) {
  // Get JS context for parsing
  dom::AutoJSAPI jsapi;
  if (!jsapi.Init(xpc::PrivilegedJunkScope())) {
    return NS_ERROR_FAILURE;
  }
  JSContext* cx = jsapi.cx();

  // Parse JSON string
  JS::Rooted<JS::Value> jsonValue(cx);
  if (!JS_ParseJSON(cx, NS_ConvertUTF8toUTF16(decodedJsonString).BeginReading(),
                    decodedJsonString.Length(), &jsonValue)) {
    return NS_ERROR_INVALID_ARG;
  }

  // Check if it's an object
  if (!jsonValue.isObject()) {
    return NS_ERROR_INVALID_ARG;
  }

  JS::Rooted<JSObject*> tokenObj(cx, &jsonValue.toObject());
  // Parse each field
  JS::Rooted<JS::Value> fieldValue(cx);

  if (JS_GetProperty(cx, tokenObj, "destination_domain", &fieldValue) &&
      fieldValue.isString()) {
    JSString* str = fieldValue.toString();
    nsAutoJSString autoStr;
    if (autoStr.init(cx, str)) {
      outToken.destinationDomain = NS_ConvertUTF16toUTF8(autoStr);
    }
  }

  if (JS_GetProperty(cx, tokenObj, "cookie_name", &fieldValue) &&
      fieldValue.isString()) {
    JSString* str = fieldValue.toString();
    nsAutoJSString autoStr;
    if (autoStr.init(cx, str)) {
      outToken.cookieName = NS_ConvertUTF16toUTF8(autoStr);
    }
  }

  if (JS_GetProperty(cx, tokenObj, "cookie_value", &fieldValue)) {
    if (fieldValue.isString()) {
      JSString* str = fieldValue.toString();
      nsAutoJSString autoStr;
      if (autoStr.init(cx, str)) {
        outToken.cookieValue = NS_ConvertUTF16toUTF8(autoStr);
      }
    }
    // If null, leave cookieValue empty
  }

  if (JS_GetProperty(cx, tokenObj, "application_id", &fieldValue) &&
      fieldValue.isString()) {
    JSString* str = fieldValue.toString();
    nsAutoJSString autoStr;
    if (autoStr.init(cx, str)) {
      outToken.packageName = NS_ConvertUTF16toUTF8(autoStr);
    }
  }

  if (JS_GetProperty(cx, tokenObj, "version_name", &fieldValue) &&
      fieldValue.isString()) {
    JSString* str = fieldValue.toString();
    nsAutoJSString autoStr;
    if (autoStr.init(cx, str)) {
      outToken.versionName = NS_ConvertUTF16toUTF8(autoStr);
    }
  }

  if (JS_GetProperty(cx, tokenObj, "global_jar", &fieldValue)) {
    if (fieldValue.isBoolean()) {
      outToken.globalJar = fieldValue.toBoolean();
    }
  }

  if (JS_GetProperty(cx, tokenObj, "access_rights", &fieldValue) &&
      fieldValue.isString()) {
    JSString* str = fieldValue.toString();
    nsAutoJSString autoStr;
    if (autoStr.init(cx, str)) {
      nsCString accessRightsStr = NS_ConvertUTF16toUTF8(autoStr);
      outToken.accessRights = accessRightsStr;
    }
  }

  return NS_OK;
}

nsresult decodeTokenString(const nsACString& encoded, nsACString& decoded) {
  const int32_t dot = encoded.FindChar('.');
  if (dot <= 0 || dot == static_cast<int32_t>(encoded.Length()) - 1) {
    return NS_ERROR_INVALID_ARG;
  }

  // Split into payloadB64 and signature
  const nsDependentCSubstring payloadB64 = Substring(encoded, 0, dot);
  const nsDependentCSubstring signature = Substring(encoded, dot + 1);

  // Base64URL decode payload
  FallibleTArray<uint8_t> payloadBytes;
  nsresult rv = mozilla::Base64URLDecode(
      payloadB64,
      mozilla::Base64URLDecodePaddingPolicy::Ignore,
      payloadBytes);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Codec) Failed to decode payload\n");
    return rv;
  }

  // Base64URL decode the provided signature
  FallibleTArray<uint8_t> signatureBytes;
  rv = mozilla::Base64URLDecode(
      signature,
      mozilla::Base64URLDecodePaddingPolicy::Ignore,
      signatureBytes);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Codec) Failed to decode signature\n");
    return rv; // Invalid signature format
  }

  // Verify HMAC signature
  // Create string_view from payload bytes for HMAC calculation
  std::string_view payloadView(reinterpret_cast<const char*>(payloadBytes.Elements()),
                               payloadBytes.Length());

  // Calculate expected HMAC
  FallibleTArray<uint8_t> expectedHmac;
  rv = hmac_sha256(payloadView, expectedHmac);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Codec) Failed to calculate HMAC\n");
    return rv;
  }

  if (!constantTimeEquals(expectedHmac, signatureBytes)) {
    return NS_ERROR_INVALID_ARG; // Invalid signature
  }

  // Convert bytes to string (UTF-8)
  if (!decoded.Assign(reinterpret_cast<const char*>(payloadBytes.Elements()),
                          payloadBytes.Length(), mozilla::fallible)) {
    printf_stderr("Byetrack (Codec) Failed to convert bytes to string\n");
    return NS_ERROR_OUT_OF_MEMORY;
  }

  printf_stderr("Byetrack (Codec) sucessfully decoded Token: %s\n", decoded.BeginReading());
  return NS_OK;
}

nsresult encodeToken(const ByetrackToken& token, nsACString& outEncoded) {
  // Get JS context for JSON serialization
  dom::AutoJSAPI jsapi;
  if (!jsapi.Init(xpc::PrivilegedJunkScope())) {
    return NS_ERROR_FAILURE;
  }
  JSContext* cx = jsapi.cx();

  // Create JS object for the token
  JS::Rooted<JSObject*> tokenObj(cx, JS_NewPlainObject(cx));
  if (!tokenObj) {
    return NS_ERROR_OUT_OF_MEMORY;
  }

  // Set properties on the object
  JS::Rooted<JSString*> jsStr(cx);
  JS::Rooted<JS::Value> jsVal(cx);

  // destination_domain
  jsStr = JS_NewStringCopyZ(cx, token.destinationDomain.get());
  if (!jsStr) return NS_ERROR_OUT_OF_MEMORY;
  jsVal.setString(jsStr);
  if (!JS_SetProperty(cx, tokenObj, "destination_domain", jsVal)) {
    return NS_ERROR_FAILURE;
  }

  // cookie_name
  jsStr = JS_NewStringCopyZ(cx, token.cookieName.get());
  if (!jsStr) return NS_ERROR_OUT_OF_MEMORY;
  jsVal.setString(jsStr);
  if (!JS_SetProperty(cx, tokenObj, "cookie_name", jsVal)) {
    return NS_ERROR_FAILURE;
  }

  // cookie_value (can be null/empty)
  if (token.cookieValue.IsEmpty()) {
    jsVal.setNull();
  } else {
    jsStr = JS_NewStringCopyZ(cx, token.cookieValue.get());
    if (!jsStr) return NS_ERROR_OUT_OF_MEMORY;
    jsVal.setString(jsStr);
  }
  if (!JS_SetProperty(cx, tokenObj, "cookie_value", jsVal)) {
    return NS_ERROR_FAILURE;
  }

  // application_id
  jsStr = JS_NewStringCopyZ(cx, token.packageName.get());
  if (!jsStr) return NS_ERROR_OUT_OF_MEMORY;
  jsVal.setString(jsStr);
  if (!JS_SetProperty(cx, tokenObj, "application_id", jsVal)) {
    return NS_ERROR_FAILURE;
  }

  // version_name
  jsStr = JS_NewStringCopyZ(cx, token.versionName.get());
  if (!jsStr) return NS_ERROR_OUT_OF_MEMORY;
  jsVal.setString(jsStr);
  if (!JS_SetProperty(cx, tokenObj, "version_name", jsVal)) {
    return NS_ERROR_FAILURE;
  }

  // global_jar
  jsVal.setBoolean(token.globalJar);
  if (!JS_SetProperty(cx, tokenObj, "global_jar", jsVal)) {
    return NS_ERROR_FAILURE;
  }

  // access_rights
  jsStr = JS_NewStringCopyZ(cx, token.accessRights.get());
  if (!jsStr) return NS_ERROR_OUT_OF_MEMORY;
  jsVal.setString(jsStr);
  if (!JS_SetProperty(cx, tokenObj, "access_rights", jsVal)) {
    return NS_ERROR_FAILURE;
  }

  // Stringify the object to JSON
  JS::Rooted<JS::Value> tokenValue(cx, JS::ObjectValue(*tokenObj));
  nsCString jsonString;
  
  // Helper function to collect JSON string - similar to nsContentUtils
  auto jsonCollector = [](const char16_t* buf, uint32_t len, void* data) {
    nsCString* str = static_cast<nsCString*>(data);
    str->Append(NS_ConvertUTF16toUTF8(nsDependentString(buf, len)));
    return true;
  };
  
  if (!JS_Stringify(cx, &tokenValue, nullptr, JS::NullHandleValue,
                    jsonCollector, &jsonString)) {
    return NS_ERROR_FAILURE;
  }

  printf_stderr("Byetrack (Codec) JSON string to encode: %s\n", jsonString.BeginReading());

  // Base64URL encode the JSON payload
  nsCString payloadB64;
  nsresult rv = mozilla::Base64URLEncode(
      jsonString.Length(),
      reinterpret_cast<const uint8_t*>(jsonString.BeginReading()),
      mozilla::Base64URLEncodePaddingPolicy::Omit,
      payloadB64);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Codec) Failed to base64url encode payload\n");
    return rv;
  }

  // Calculate HMAC signature for the JSON payload (not the base64 encoded version)
  std::string_view payloadView(jsonString.BeginReading(), jsonString.Length());
  FallibleTArray<uint8_t> hmacBytes;
  rv = hmac_sha256(payloadView, hmacBytes);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Codec) Failed to calculate HMAC\n");
    return rv;
  }

  // Base64URL encode the signature
  nsCString signatureB64;
  rv = mozilla::Base64URLEncode(
      hmacBytes.Length(),
      hmacBytes.Elements(),
      mozilla::Base64URLEncodePaddingPolicy::Omit,
      signatureB64);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Codec) Failed to base64url encode signature\n");
    return rv;
  }

  // Combine payload and signature with a dot
  outEncoded.Assign(payloadB64);
  outEncoded.AppendLiteral(".");
  outEncoded.Append(signatureB64);

  printf_stderr("Byetrack (Codec) successfully encoded token: %s\n", outEncoded.BeginReading());
  return NS_OK;
}

nsresult validateTokenFields(const nsACString &expectedPackageName, const nsACString &expectedVersionName, const nsACString &expectedDomainName, const ByetrackToken &token) {
  if (token.packageName != expectedPackageName) {
    printf_stderr("Byetrack (Codec) Invalid package name: %s (expected: %s)\n", token.packageName.get(), expectedPackageName.BeginReading());
    return NS_ERROR_INVALID_ARG;
  }
  if (token.versionName != expectedVersionName) {
    printf_stderr("Byetrack (Codec) Invalid version name: %s (expected: %s)\n", token.versionName.get(), expectedVersionName.BeginReading());
    return NS_ERROR_INVALID_ARG;
  }
  if (token.destinationDomain != expectedDomainName) {
    printf_stderr("Byetrack (Codec) Invalid destination domain: %s (expected: %s)\n", token.destinationDomain.get(), expectedDomainName.BeginReading());
    return NS_ERROR_INVALID_ARG;
  }
  printf_stderr("Byetrack (Codec) Token validation succeeded\n");
  return NS_OK;
}

nsresult getFinalTokensCookieHeader(const nsTArray<ByetrackToken>& finalTokens, nsACString &outHeader) {
  // Clear the output header
  outHeader.Truncate();
  
  // If no tokens, return empty header
  if (finalTokens.IsEmpty()) {
    return NS_OK;
  }
  
  // Build Cookie header in the format: "name1=value1; name2=value2; name3=value3"
  bool first = true;
  
  for (const ByetrackToken& token : finalTokens) {
    // Skip tokens without cookie name (invalid tokens)
    if (token.cookieName.IsEmpty()) {
      continue;
    }
    
    // Add separator for subsequent cookies
    if (!first) {
      outHeader.AppendLiteral("; ");
    }
    first = false;

    outHeader.Append(token.cookieName);
    outHeader.AppendLiteral("=");
    outHeader.Append(token.cookieValue);
  }

  return NS_OK;
}

constexpr uint8_t kTokenBinVer = 1;

MOZ_ALWAYS_INLINE void WriteU8(nsCString& out, uint8_t v) {
  out.Append(char(v));
}
MOZ_ALWAYS_INLINE void WriteU16(nsCString& out, uint16_t v) {
  out.Append(char(v & 0xFF));
  out.Append(char((v >> 8) & 0xFF));
}
MOZ_ALWAYS_INLINE void WriteStr16(nsCString& out, const nsACString& s) {
  const uint32_t n = s.Length();
  MOZ_RELEASE_ASSERT(n <= 0xFFFF, "string too long for U16 length");
  WriteU16(out, uint16_t(n));
  out.Append(s);
}

MOZ_ALWAYS_INLINE bool ReadU8(const uint8_t*& p, const uint8_t* end, uint8_t& v) {
  if (p >= end) return false;
  v = *p++;
  return true;
}
MOZ_ALWAYS_INLINE bool ReadU16(const uint8_t*& p, const uint8_t* end, uint16_t& v) {
  if (size_t(end - p) < 2) return false;
  v = uint16_t(p[0]) | (uint16_t(p[1]) << 8);
  p += 2;
  return true;
}
MOZ_ALWAYS_INLINE bool ReadStr16(const uint8_t*& p, const uint8_t* end, nsCString& s) {
  uint16_t n;
  if (!ReadU16(p, end, n)) return false;
  if (size_t(end - p) < n)  return false;
  s.Assign(reinterpret_cast<const char*>(p), n);
  p += n;
  return true;
}

nsCString SerializeTokens(const nsTArray<ByetrackToken>& tokens)
{
  // Pre-size roughly to avoid reallocations.
  size_t cap = 1 + 2; // ver + count
  for (const auto& t : tokens) {
    cap += 1 // flags
         + 2 + t.destinationDomain.Length()
         + 2 + t.cookieName.Length()
         + 2 + t.cookieValue.Length()
         + 2 + t.packageName.Length()
         + 2 + t.versionName.Length()
         + 2 + t.accessRights.Length();
  }

  nsCString out;
  out.SetCapacity(cap);

  WriteU8(out, kTokenBinVer);
  WriteU16(out, uint16_t(tokens.Length()));

  for (const auto& t : tokens) {
    uint8_t flags = 0;
    if (t.globalJar) flags |= 0x01; // bit0

    WriteU8(out, flags);
    WriteStr16(out, t.destinationDomain);
    WriteStr16(out, t.cookieName);
    WriteStr16(out, t.cookieValue);
    WriteStr16(out, t.packageName);
    WriteStr16(out, t.versionName);
    WriteStr16(out, t.accessRights);
  }

  return out;
}

bool DeserializeTokens(const nsACString& bin, nsTArray<ByetrackToken>& out)
{
  out.Clear();

  const uint8_t* p   = reinterpret_cast<const uint8_t*>(bin.BeginReading());
  const uint8_t* end = reinterpret_cast<const uint8_t*>(bin.EndReading());
  if (!p || !end || p == end) return false;

  uint8_t ver;
  if (!ReadU8(p, end, ver) || ver != kTokenBinVer) {
    return false;
  }

  uint16_t count;
  if (!ReadU16(p, end, count)) {
    return false;
  }

  out.SetCapacity(count);

  for (uint16_t i = 0; i < count; ++i) {
    uint8_t flags;
    if (!ReadU8(p, end, flags)) return false;

    ByetrackToken t;
    if (!ReadStr16(p, end, t.destinationDomain)) return false;
    if (!ReadStr16(p, end, t.cookieName))       return false;
    if (!ReadStr16(p, end, t.cookieValue))      return false;
    if (!ReadStr16(p, end, t.packageName))      return false;
    if (!ReadStr16(p, end, t.versionName))      return false;
    if (!ReadStr16(p, end, t.accessRights))     return false;

    t.globalJar = (flags & 0x01) != 0;

    out.AppendElement(std::move(t));
  }

  // Must have consumed exactly all data (optional strictness)
  // if (p != end) return false;

  return true;
}

nsresult testEncodeDecodeRoundtrip() {
  // Create a test token
  ByetrackToken testToken;
  testToken.destinationDomain = "example.com";
  testToken.cookieName = "test_cookie";
  testToken.cookieValue = "test_value";
  testToken.packageName = "com.example.app";
  testToken.versionName = "1.0.0";
  testToken.accessRights = "READ_WRITE";
  testToken.globalJar = true;

  printf_stderr("Byetrack (Codec) Testing encode/decode roundtrip...\n");
  printf_stderr("Byetrack (Codec) Original token: %s\n", testToken.toString().BeginReading());

  // Encode the token
  nsCString encodedToken;
  nsresult rv = encodeToken(testToken, encodedToken);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Codec) Failed to encode token\n");
    return rv;
  }
  printf_stderr("Byetrack (Codec) Encoded token: %s\n", encodedToken.BeginReading());

  // Decode the encoded token
  nsCString decodedJson;
  rv = decodeTokenString(encodedToken, decodedJson);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Codec) Failed to decode token\n");
    return rv;
  }
  printf_stderr("Byetrack (Codec) Decoded JSON: %s\n", decodedJson.BeginReading());

  // Parse the decoded JSON back to a token
  ByetrackToken decodedToken;
  rv = parseSingleToken(decodedJson, decodedToken);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Codec) Failed to parse decoded token\n");
    return rv;
  }
  printf_stderr("Byetrack (Codec) Decoded token: %s\n", decodedToken.toString().BeginReading());

  // Re-encode the decoded token  
  nsCString reEncodedToken;
  rv = encodeToken(decodedToken, reEncodedToken);
  if (NS_FAILED(rv)) {
    printf_stderr("Byetrack (Codec) Failed to re-encode token\n");
    return rv;
  }
  printf_stderr("Byetrack (Codec) Re-encoded token: %s\n", reEncodedToken.BeginReading());

  // Check if encodedToken == reEncodedToken
  if (encodedToken.Equals(reEncodedToken)) {
    printf_stderr("Byetrack (Codec) ✅ SUCCESS: encode(decode(encodedToken)) == encodedToken\n");
    return NS_OK;
  }
  
  printf_stderr("Byetrack (Codec) ❌ FAILED: encode(decode(encodedToken)) != encodedToken\n");
  printf_stderr("Byetrack (Codec) Original:  %s\n", encodedToken.BeginReading());
  printf_stderr("Byetrack (Codec) Re-encoded: %s\n", reEncodedToken.BeginReading());
  return NS_ERROR_FAILURE;
}

} // namespace mozilla::byetrack