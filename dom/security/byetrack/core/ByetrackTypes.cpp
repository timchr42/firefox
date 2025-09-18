#include "ByetrackTypes.h"
#include "nsString.h"

namespace mozilla::byetrack {

// Convert string to AccessRights
AccessRights StringToAccessRights(const nsACString& str) {
  if (str.EqualsLiteral("READ")) {
    return AccessRights::READ;
  }
  if (str.EqualsLiteral("WRITE")) {
    return AccessRights::WRITE;
  }
  if (str.EqualsLiteral("READ_WRITE")) {
    return AccessRights::READ_WRITE;
  }
  return AccessRights::NONE;
}

} // namespace mozilla::byetrack