#ifndef DOM_SECURITY_BYETRACK_BYETRACKTOKENS_H_
#define DOM_SECURITY_BYETRACK_BYETRACKTOKENS_H_

#include "nsString.h"  // for nsCString, nsACString
#include "nsTArray.h"

// Forward declarations
class nsDocShellLoadState;
namespace mozilla {
namespace net {
class LoadInfo;
}
}

namespace mozilla::byetrack {

struct ByetrackToken {
  nsCString destinationDomain;
  nsCString cookieName;
  nsCString cookieValue;
  nsCString packageName;
  nsCString versionName;
  nsCString accessRights;
  bool globalJar = false;

  // Utility methods
  bool isWildcard() const {
    return cookieName.EqualsLiteral("*");
  }

  bool isPredefined(const nsACString& aCookieName) const {
    return cookieName.Equals(aCookieName) && cookieValue.EqualsLiteral("*");
  }

  bool isDefault() const {
    return versionName.EqualsLiteral("DEFAULT");
  }

  void SetCookieName(const nsACString& aName) {
    cookieName = aName;
  }

  void SetCookieValue(const nsACString& aValue) {
    cookieValue = aValue;
  }

  bool canRead() const {
    return accessRights == "READ" || accessRights == "READ_WRITE";
  }

  bool canWrite() const {
    return accessRights == "WRITE" || accessRights == "READ_WRITE";
  }

  bool hasAnyAccess() const {
    return accessRights != "NONE";
  }

  nsCString toString() const {
    nsCString repr;
    repr.AppendLiteral("{ domain: ");
    repr.Append(destinationDomain);
    repr.AppendLiteral(", name: ");
    repr.Append(cookieName);
    repr.AppendLiteral(", value: ");
    repr.Append(cookieValue);
    repr.AppendLiteral(", package: ");
    repr.Append(packageName);
    repr.AppendLiteral(", version: ");
    repr.Append(versionName);
    repr.AppendLiteral(", access: ");
    repr.Append(accessRights);
    repr.AppendLiteral(", globalJar: ");
    repr.Append(globalJar ? "true" : "false");
    repr.AppendLiteral(" }");
    return repr;
  }
};

enum class ByetrackCookieAction {
  StoreNormally,
  CapturePredefined,
  CaptureWildcard
};

struct ByetrackCookieDecision {
  ByetrackCookieAction action;
  ByetrackToken* token;  // nullptr unless Capture*
};

}

#endif // DOM_SECURITY_BYETRACK_BYETRACKTOKENS_H_
