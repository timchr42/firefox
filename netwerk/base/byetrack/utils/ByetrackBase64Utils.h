#ifndef DOM_SECURITY_BYETRACK_UTILS_BYETRACKBASE64UTILS_H_
#define DOM_SECURITY_BYETRACK_UTILS_BYETRACKBASE64UTILS_H_

#include "nsError.h"
#include "nsStringFwd.h"
#include "nsTArray.h"

namespace mozilla::byetrack {

/**
 * Centralized Base64 URL-safe encoding/decoding utilities for Byetrack tokens.
 * All Base64 operations should go through these functions for consistency.
 */
class Base64Utils {
public:
  /**
   * Encode binary data to Base64URL format (no padding)
   * Used for token payload and encrypted data encoding
   */
  static nsresult Encode(const uint8_t* aData, 
                        uint32_t aLength, 
                        nsACString& aEncodedString);

  /**
   * Convenience overload for FallibleTArray
   */
  static nsresult Encode(const FallibleTArray<uint8_t>& aData, 
                        nsACString& aEncodedString);

  /**
   * Decode Base64URL string to binary data
   * Used for token payload and encrypted data decoding
   */
  static nsresult Decode(const nsACString& aEncodedString, 
                        FallibleTArray<uint8_t>& aDecodedData);

  /**
   * Validate that a string is valid Base64URL format
   * Useful for early validation before attempting decode
   */
  static bool IsValidBase64Url(const nsACString& aString);

  /**
   * Get expected decoded size for a Base64URL string
   * Useful for pre-allocating buffers
   */
  static uint32_t GetDecodedSize(const nsACString& aEncodedString);

private:
  // Prevent instantiation - this is a utility class
  Base64Utils() = delete;
  ~Base64Utils() = delete;
  Base64Utils(const Base64Utils&) = delete;
  Base64Utils& operator=(const Base64Utils&) = delete;
};

} // namespace mozilla::byetrack

#endif // DOM_SECURITY_BYETRACK_UTILS_BYETRACKBASE64UTILS_H_