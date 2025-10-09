#include "ByetrackTokenParser.h"
#include "js/Array.h"
#include "js/JSON.h"
#include "js/PropertyAndElement.h"
#include "xpcpublic.h"
#include "mozilla/dom/ScriptSettings.h"
#include "nsJSUtils.h"
#include "core/ByetrackConstants.h"

namespace mozilla::byetrack {

nsresult TokenParser::ParseTokenBlob(const nsACString& aBlob,
                                    nsTArray<nsCString>& outTokenStrings) {
  if (aBlob.IsEmpty()) {
    return NS_OK; // no tokens => no work to do
  }
  printf_stderr("Byetrack (Parser) parsing token blob: %s\n", aBlob.BeginReading());

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

  printf_stderr("Byetrack (Parser) Found %d tokens in blob\n", length);

  // Extract each token string from the array
  for (uint32_t i = 0; i < length; i++) {
    JS::Rooted<JS::Value> element(cx);
    if (!JS_GetElement(cx, jsonArray, i, &element)) {
      printf_stderr("Byetrack (Parser) failed to get element at index %d\n", i);
      continue;
    }

    if (!element.isString()) {
      printf_stderr("Byetrack (Parser) element at index %d is not a string\n", i);
      continue;
    }

    JS::Rooted<JSString*> jsStr(cx, element.toString());
    nsAutoJSString autoStr;
    if (!autoStr.init(cx, jsStr)) {
      printf_stderr("Byetrack (Parser) failed to convert string at index %d\n", i);
      continue;
    }
    
    nsCString tokenString = NS_ConvertUTF16toUTF8(autoStr);
    printf_stderr("Byetrack (Parser) extracted token at index %d: %s\n", i, tokenString.BeginReading());
    
    outTokenStrings.AppendElement(tokenString);
  }
  
  return NS_OK;
}

nsresult TokenParser::ParseSingleToken(const nsACString& aDecodedJsonString,
                                      ByetrackToken& outToken) {
  if (aDecodedJsonString.IsEmpty()) {
    return NS_ERROR_INVALID_ARG;
  }

  // Get JS context for parsing
  dom::AutoJSAPI jsapi;
  if (!jsapi.Init(xpc::PrivilegedJunkScope())) {
    return NS_ERROR_FAILURE;
  }
  JSContext* cx = jsapi.cx();

  // Parse JSON
  JS::Rooted<JS::Value> jsonValue(cx);
  if (!JS_ParseJSON(cx, NS_ConvertUTF8toUTF16(aDecodedJsonString).BeginReading(),
                    aDecodedJsonString.Length(), &jsonValue)) {
    return NS_ERROR_INVALID_ARG;
  }

  if (!jsonValue.isObject()) {
    return NS_ERROR_INVALID_ARG;
  }

  JS::Rooted<JSObject*> obj(cx, &jsonValue.toObject());

  // Helper lambda to extract string property
  auto extractStringProp = [&](const char* propName, nsCString& outStr) -> bool {
    JS::Rooted<JS::Value> val(cx);
    if (!JS_GetProperty(cx, obj, propName, &val) || !val.isString()) {
      return false;
    }
    JS::Rooted<JSString*> jsStr(cx, val.toString());
    nsAutoJSString autoStr;
    if (!autoStr.init(cx, jsStr)) {
      return false;
    }
    outStr = NS_ConvertUTF16toUTF8(autoStr);
    return true;
  };

  // Helper lambda to extract boolean property
  auto extractBoolProp = [&](const char* propName, bool& outBool) -> bool {
    JS::Rooted<JS::Value> val(cx);
    if (!JS_GetProperty(cx, obj, propName, &val) || !val.isBoolean()) {
      return false;
    }
    outBool = val.toBoolean();
    return true;
  };

  // Extract all required properties using constants
  if (!extractStringProp(json::DESTINATION_DOMAIN, outToken.destinationDomain) ||
      !extractStringProp(json::COOKIE_NAME, outToken.cookieName) ||
      !extractStringProp(json::APPLICATION_ID, outToken.packageName) ||
      !extractStringProp(json::VERSION_NAME, outToken.versionName) ||
      !extractBoolProp(json::GLOBAL_JAR, outToken.globalJar)) {
    return NS_ERROR_INVALID_ARG;
  }

  // Extract optional cookie_value (can be null)
  JS::Rooted<JS::Value> cookieVal(cx);
  if (JS_GetProperty(cx, obj, json::COOKIE_VALUE, &cookieVal)) {
    if (cookieVal.isString()) {
      JS::Rooted<JSString*> jsStr(cx, cookieVal.toString());
      nsAutoJSString autoStr;
      if (autoStr.init(cx, jsStr)) {
        outToken.cookieValue = NS_ConvertUTF16toUTF8(autoStr);
      }
    }
    // If null or not string, leave cookieValue empty
  }

  // Extract access_rights
  nsCString accessRightsStr;
  if (extractStringProp(json::ACCESS_RIGHTS, accessRightsStr)) {
    outToken.SetAccessRights(accessRightsStr);
  }

  printf_stderr("Byetrack (Parser) Parsed token: %s\n", outToken.ToString().BeginReading());
  return NS_OK;
}

} // namespace mozilla::byetrack