#ifndef DOM_SECURITY_BYETRACK_BYETRACKAPI_H_
#define DOM_SECURITY_BYETRACK_BYETRACKAPI_H_

/**
 * Byetrack Token System - Main Public API
 *
 * This is the primary interface for the Byetrack capability token system.
 * Use this header instead of including individual component headers directly.
 */

#include "nsTArray.h"
#include "nsString.h"
#include "nsError.h"

// Forward declarations to avoid exposing internal details
namespace mozilla::byetrack {
  class ByetrackToken;
}

namespace mozilla::byetrack::api {

/**
 * Main token parsing and validation interface
 */
nsresult ParseTokenBlob(const nsACString& aTokenBlob,
                       const nsACString& aDomainName,
                       const nsACString& aPackageName,
                       const nsACString& aVersionName,
                       nsTArray<ByetrackToken>& outTokens);

/**
 * Token encoding (for testing and utilities)
 */
nsresult EncodeToken(const ByetrackToken& token,
                    nsACString& outEncodedToken);

nsresult EncodeEncryptedToken(const ByetrackToken& token,
                             nsACString& outEncryptedToken);

/**
 * Token decoding (for testing and utilities)
 */
nsresult DecodeTokenString(const nsACString& encodedToken,
                          nsACString& outDecodedJson);

nsresult DecodeEncryptedTokenString(const nsACString& encryptedToken,
                                   nsACString& outDecodedJson);

/**
 * Cookie header generation
 */
nsresult GetCookieHeader(const nsTArray<ByetrackToken>& tokens,
                        nsACString& outCookieHeader);

/**
 * Testing utilities
 */
nsresult RunEncodeDecodeTest();
nsresult RunEncryptedEncodeDecodeTest();

} // namespace mozilla::byetrack::api

// Legacy compatibility - re-export old interface in the old namespace
namespace mozilla::byetrack {
  using namespace api;
  
  // Keep old function names for compatibility
  inline nsresult parseTokenBlob(const nsACString& aBlob,
                                const nsACString& aDomainName,
                                const nsACString& aPackageName,
                                const nsACString& aVersionName,
                                nsTArray<ByetrackToken>& outTokens) {
    return ParseTokenBlob(aBlob, aDomainName, aPackageName, aVersionName, outTokens);
  }

  inline nsresult getFinalTokensCookieHeader(const nsTArray<ByetrackToken>& tokens,
                                            nsACString& outHeader) {
    return GetCookieHeader(tokens, outHeader);
  }
}

#endif // DOM_SECURITY_BYETRACK_BYETRACKAPI_H_