#include "ByetrackBase64Utils.h"
#include "mozilla/Base64.h"

namespace mozilla::byetrack {

nsresult Base64Utils::Encode(const uint8_t* aData, 
                            uint32_t aLength, 
                            nsACString& aEncodedString) {
  if (!aData && aLength > 0) {
    return NS_ERROR_INVALID_ARG;
  }

  return mozilla::Base64URLEncode(aLength, aData,
                                  mozilla::Base64URLEncodePaddingPolicy::Omit,
                                  aEncodedString);
}

nsresult Base64Utils::Encode(const FallibleTArray<uint8_t>& aData, 
                            nsACString& aEncodedString) {
  return Encode(aData.Elements(), aData.Length(), aEncodedString);
}

nsresult Base64Utils::Decode(const nsACString& aEncodedString, 
                            FallibleTArray<uint8_t>& aDecodedData) {
  if (aEncodedString.IsEmpty()) {
    return NS_ERROR_INVALID_ARG;
  }

  return mozilla::Base64URLDecode(aEncodedString,
                                  mozilla::Base64URLDecodePaddingPolicy::Ignore,
                                  aDecodedData);
}

bool Base64Utils::IsValidBase64Url(const nsACString& aString) {
  if (aString.IsEmpty()) {
    return false;
  }

  // Base64URL uses A-Z, a-z, 0-9, -, _
  // No padding (=) should be present in URL-safe encoding
  for (uint32_t i = 0; i < aString.Length(); i++) {
    char c = aString.CharAt(i);
    if (!((c >= 'A' && c <= 'Z') ||
          (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') ||
          c == '-' || c == '_')) {
      return false;
    }
  }
  
  return true;
}

uint32_t Base64Utils::GetDecodedSize(const nsACString& aEncodedString) {
  if (aEncodedString.IsEmpty()) {
    return 0;
  }
  
  // Base64 encodes 3 bytes into 4 characters
  // For URL-safe encoding without padding, we need to calculate carefully
  uint32_t len = aEncodedString.Length();
  uint32_t decodedSize = (len * 3) / 4;
  
  // Adjust for missing padding
  uint32_t remainder = len % 4;
  if (remainder == 2) {
    decodedSize += 1;
  } else if (remainder == 3) {
    decodedSize += 2;
  }
  
  return decodedSize;
}

} // namespace mozilla::byetrack