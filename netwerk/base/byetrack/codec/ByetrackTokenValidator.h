#ifndef DOM_SECURITY_BYETRACK_CODEC_BYETRACKTOKENVALIDATOR_H_
#define DOM_SECURITY_BYETRACK_CODEC_BYETRACKTOKENVALIDATOR_H_

#include "nsError.h"
#include "../core/ByetrackToken.h"

namespace mozilla::byetrack {

/**
 * Handles token validation logic.
 * Centralizes all validation rules and domain matching.
 */
class TokenValidator {
public:
  /**
   * Validate token fields against expected values
   */
  static nsresult ValidateTokenFields(const nsACString& aExpectedPackageName,
                                     const nsACString& aExpectedVersionName,
                                     const nsACString& aExpectedDomainName,
                                     const ByetrackToken& aToken);

  /**
   * Check if the expected domain matches the token's destination domain.
   * Supports wildcard domains (e.g., *.example.com matches sub.example.com)
   */
  static bool IsValidDomainMatch(const nsACString& aExpectedDomain, 
                                const nsACString& aTokenDomain);

  /**
   * Validate that a token has all required fields
   */
  static bool IsTokenComplete(const ByetrackToken& aToken);

private:
  TokenValidator() = delete;
  ~TokenValidator() = delete;
  TokenValidator(const TokenValidator&) = delete;
  TokenValidator& operator=(const TokenValidator&) = delete;
};

} // namespace mozilla::byetrack

#endif // DOM_SECURITY_BYETRACK_CODEC_BYETRACKTOKENVALIDATOR_H_