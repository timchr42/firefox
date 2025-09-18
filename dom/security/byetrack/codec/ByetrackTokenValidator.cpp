#include "ByetrackTokenValidator.h"
#include "../core/ByetrackConstants.h"

namespace mozilla::byetrack {

nsresult TokenValidator::ValidateTokenFields(const nsACString& aExpectedPackageName,
                                           const nsACString& aExpectedVersionName,
                                           const nsACString& aExpectedDomainName,
                                           const ByetrackToken& aToken) {
  // Validate package name
  if (!aToken.packageName.Equals(aExpectedPackageName)) {
    printf_stderr("Byetrack (Validator) Package name mismatch: expected '%s', got '%s'\n",
                  aExpectedPackageName.BeginReading(), aToken.packageName.BeginReading());
    return NS_ERROR_INVALID_ARG;
  }

  // Validate version name
  if (!aToken.versionName.Equals(aExpectedVersionName)) {
    printf_stderr("Byetrack (Validator) Version name mismatch: expected '%s', got '%s'\n",
                  aExpectedVersionName.BeginReading(), aToken.versionName.BeginReading());
    return NS_ERROR_INVALID_ARG;
  }

  // Validate domain name with wildcard support
  if (!IsValidDomainMatch(aExpectedDomainName, aToken.destinationDomain)) {
    printf_stderr("Byetrack (Validator) Domain mismatch: expected '%s', token domain '%s'\n",
                  aExpectedDomainName.BeginReading(), aToken.destinationDomain.BeginReading());
    return NS_ERROR_INVALID_ARG;
  }

  // Validate token completeness
  if (!IsTokenComplete(aToken)) {
    printf_stderr("Byetrack (Validator) Token is incomplete\n");
    return NS_ERROR_INVALID_ARG;
  }

  printf_stderr("Byetrack (Validator) Token validation successful\n");
  return NS_OK;
}

bool TokenValidator::IsValidDomainMatch(const nsACString& aExpectedDomain,
                                       const nsACString& aTokenDomain) {
  if (aExpectedDomain.IsEmpty() || aTokenDomain.IsEmpty()) {
    return false;
  }

  // Exact match
  if (aExpectedDomain.Equals(aTokenDomain)) {
    return true;
  }

  // Wildcard match (token domain starts with *.)
  if (aTokenDomain.Find("*.") == 0) {
    nsDependentCSubstring baseDomain = Substring(aTokenDomain, 2); // Remove "*."
    
    // Check if expected domain ends with the base domain
    if (aExpectedDomain.Find(baseDomain) != kNotFound) {
      // Make sure it's a proper subdomain match
      nsCString expectedWithDot;
      expectedWithDot.AssignLiteral(".");
      expectedWithDot.Append(baseDomain);
      return aExpectedDomain.Equals(baseDomain) || 
             aExpectedDomain.Find(expectedWithDot) != kNotFound;
    }
  }

  return false;
}

bool TokenValidator::IsTokenComplete(const ByetrackToken& aToken) {
  return !aToken.destinationDomain.IsEmpty() &&
         !aToken.cookieName.IsEmpty() &&
         !aToken.packageName.IsEmpty() &&
         !aToken.versionName.IsEmpty();
}

bool TokenValidator::IsValidPackageName(const nsACString& aPackageName) {
  if (aPackageName.IsEmpty()) {
    return false;
  }
  
  // Basic validation - should contain at least one dot for proper package naming
  return aPackageName.Find(".") != kNotFound;
}

bool TokenValidator::IsValidVersionName(const nsACString& aVersionName) {
  if (aVersionName.IsEmpty()) {
    return false;
  }
  
  // Allow "DEFAULT" or version numbers
  return aVersionName.Equals(nsDependentCString(token::DEFAULT_VERSION)) ||
         aVersionName.Find(".") != kNotFound; // Simple version check
}

bool TokenValidator::IsValidDomainName(const nsACString& aDomainName) {
  if (aDomainName.IsEmpty()) {
    return false;
  }
  
  // Basic domain validation - should contain at least one dot unless it's a wildcard
  return aDomainName.Find(".") != kNotFound || 
         aDomainName.Find("*") == 0;
}

} // namespace mozilla::byetrack