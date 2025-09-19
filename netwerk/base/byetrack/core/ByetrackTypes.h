#ifndef DOM_SECURITY_BYETRACK_CORE_BYETRACKTYPES_H_
#define DOM_SECURITY_BYETRACK_CORE_BYETRACKTYPES_H_

#include "nsError.h"
#include "nsStringFwd.h"

namespace mozilla::byetrack {

// Access rights enumeration
enum class AccessRights {
  NONE,
  READ,
  WRITE,
  READ_WRITE
};

// Token format types
enum class TokenFormat {
  STANDARD,      // Regular base64url encoded token
  ENCRYPTED      // AES encrypted token
};

// Result types for better error handling
enum class ByetrackResult {
  SUCCESS,
  INVALID_TOKEN,
  CRYPTO_ERROR,
  PARSE_ERROR,
  VALIDATION_ERROR,
  MEMORY_ERROR,
  UNKNOWN_ERROR
};

// Convert ByetrackResult to nsresult
inline nsresult ToNSResult(ByetrackResult result) {
  switch (result) {
    case ByetrackResult::SUCCESS:
      return NS_OK;
    case ByetrackResult::INVALID_TOKEN:
    case ByetrackResult::PARSE_ERROR:
    case ByetrackResult::VALIDATION_ERROR:
      return NS_ERROR_INVALID_ARG;
    case ByetrackResult::CRYPTO_ERROR:
      return NS_ERROR_FAILURE;
    case ByetrackResult::MEMORY_ERROR:
      return NS_ERROR_OUT_OF_MEMORY;
    default:
      return NS_ERROR_FAILURE;
  }
}

// Convert AccessRights to string
inline const char* AccessRightsToString(AccessRights rights) {
  switch (rights) {
    case AccessRights::READ:
      return "READ";
    case AccessRights::WRITE:
      return "WRITE";
    case AccessRights::READ_WRITE:
      return "READ_WRITE";
    default:
      return "NONE";
  }
}

// Convert string to AccessRights - declaration only
AccessRights StringToAccessRights(const nsACString& str);

// Cookie decision types for cookie handling
enum class ByetrackCookieAction {
  StoreNormally,
  CapturePredefined,
  CaptureWildcard,
  Reject
};

// Forward declaration for ByetrackToken
class ByetrackToken;

struct ByetrackCookieDecision {
  ByetrackCookieAction action;
  ByetrackToken* token = nullptr;  // nullptr unless Capture*
};

} // namespace mozilla::byetrack

#endif // DOM_SECURITY_BYETRACK_CORE_BYETRACKTYPES_H_