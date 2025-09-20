#ifndef DOM_SECURITY_BYETRACK_CORE_BYETRACKTOKEN_H_
#define DOM_SECURITY_BYETRACK_CORE_BYETRACKTOKEN_H_

#include "nsTArray.h"
#include "nsString.h"
#include "ByetrackTypes.h"
#include "ByetrackConstants.h"

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

  // Utility methods
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
    result.AppendPrintf("Token{domain=%s, cookie=%s, package=%s, version=%s, rights=%s, global=%s}",
                       destinationDomain.BeginReading(),
                       cookieName.BeginReading(),
                       packageName.BeginReading(),
                       versionName.BeginReading(),
                       AccessRightsToString(accessRights),
                       globalJar ? "true" : "false");
    return result;
  }

  // Setters with validation
  void SetCookieName(const nsACString& aName) {
    cookieName = aName;
  }

  void SetCookieValue(const nsACString& aValue) {
    cookieValue = aValue;
  }

  void SetAccessRights(AccessRights aRights) {
    accessRights = aRights;
  }

  void SetAccessRights(const nsACString& aRightsStr) {
    accessRights = StringToAccessRights(aRightsStr);
  }

  // Legacy compatibility - will be removed after refactoring
  nsCString toString() const { return ToString(); }
};

} // namespace mozilla::byetrack

#endif // DOM_SECURITY_BYETRACK_CORE_BYETRACKTOKEN_H_