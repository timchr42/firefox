#ifndef DOM_SECURITY_BYETRACK_CORE_BYETRACKTOKEN_H_
#define DOM_SECURITY_BYETRACK_CORE_BYETRACKTOKEN_H_

#include "nsString.h"
#include "mozilla/byetrack/core/ByetrackTypes.h"
#include "mozilla/byetrack/core/ByetrackConstants.h"

namespace mozilla::byetrack {

/**
 * Represents a capability token with improved type safety and validation
 */
class ByetrackToken {
public:
  // Constructor
  ByetrackToken() = default;

  ByetrackToken(const nsACString& aDomain,
                const nsACString& aCookieName,
                const nsACString& aCookieValue,
                const nsACString& aPackageName,
                const nsACString& aVersionName,
                AccessRights aRights,
                bool aGlobalJar)
    : destinationDomain(aDomain)
    , cookieName(aCookieName)
    , cookieValue(aCookieValue)
    , packageName(aPackageName)
    , versionName(aVersionName)
    , accessRights(aRights)
    , globalJar(aGlobalJar) {}

  // Data members
  nsCString destinationDomain;
  nsCString cookieName;
  nsCString cookieValue;
  nsCString packageName;
  nsCString versionName;
  AccessRights accessRights = AccessRights::NONE;
  bool globalJar = false;

  nsCString cachedEncodedToken;

  // Utility methods

  bool HasCachedEncoded() const {
    return !cachedEncodedToken.IsEmpty();
  }

  void SetCachedEncoded(const nsACString& aEncoded) {
    if (!cachedEncodedToken.Equals(aEncoded)) {
      cachedEncodedToken = aEncoded;
    }
  }

  const nsCString& GetCachedEncoded() const {
    return cachedEncodedToken;
  }

  bool IsDeleted() const {
    return cookieName.IsEmpty();
  }

  bool IsWildcard() const {
    return cookieName.Equals(token::WILDCARD_VALUE);
  }

  bool IsPredefined(const nsACString& aCookieName) const {
    return cookieName.Equals(aCookieName) &&
           cookieValue.Equals(token::WILDCARD_VALUE);
  }

  bool IsAmbient() const {
    return destinationDomain.Equals(token::WILDCARD_VALUE) &&
           cookieName.Equals(token::WILDCARD_VALUE) &&
           cookieValue.Equals(token::WILDCARD_VALUE);
  }

  bool IsDefault() const {
    return versionName.Equals(token::DEFAULT_VERSION);
  }

  bool CanRead() const {
    return accessRights == AccessRights::READ ||
           accessRights == AccessRights::READ_WRITE;
  }

  bool CanWrite() const {
    return accessRights == AccessRights::WRITE ||
           accessRights == AccessRights::READ_WRITE;
  }

  // Validation
  bool IsValid() const {
    return !destinationDomain.IsEmpty() &&
           !cookieName.IsEmpty() &&
           !packageName.IsEmpty() &&
           !versionName.IsEmpty();
  }

  // String representation for debugging
  nsCString ToString() const {
    nsCString result;
    result.AppendPrintf("Token{domain=%s, cookie_name=%s, cookie_value=%s, package=%s, version=%s, rights=%s, global=%s}",
                       destinationDomain.BeginReading(),
                       cookieName.BeginReading(),
                       cookieValue.BeginReading(),
                       packageName.BeginReading(),
                       versionName.BeginReading(),
                       AccessRightsToString(accessRights),
                       globalJar ? "true" : "false");
    return result;
  }

  char* ToCharArray() const {
    nsCString str = ToString();
    char* cstr = new char[str.Length() + 1];
    strcpy(cstr, str.BeginReading());
    return cstr;
  }

  // Setters with validation
  void SetCookieName(const nsACString& aName) {
    if (!cookieName.Equals(aName)) {
      cachedEncodedToken.Truncate();  // content changed -> cache is stale
    }
    cookieName = aName;
  }

  void SetCookieValue(const nsACString& aValue) {
    if (!cookieValue.Equals(aValue)) {
      cachedEncodedToken.Truncate();  // content changed -> cache is stale
    }
    cookieValue = aValue;
  }

  void SetAccessRights(AccessRights aRights) {
    if (accessRights != aRights) {
      cachedEncodedToken.Truncate();  // content changed -> cache is stale
    }
    accessRights = aRights;
  }

  void SetAccessRights(const nsACString& aRightsStr) {
    AccessRights parsed = StringToAccessRights(aRightsStr);
    if (accessRights != parsed) {
      cachedEncodedToken.Truncate();
    }
    accessRights = parsed;
  }

  // Legacy compatibility - will be removed after refactoring
  nsCString toString() const { return ToString(); }
};

} // namespace mozilla::byetrack

#endif // DOM_SECURITY_BYETRACK_CORE_BYETRACKTOKEN_H_
