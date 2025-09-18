#include "nsTArray.h"
#include "nsString.h"
#include "../core/ByetrackConstants.h"

namespace mozilla::byetrack {

nsresult hmac_sha256(std::string_view msg, FallibleTArray<uint8_t>& outHmac);

bool constantTimeEquals(const FallibleTArray<uint8_t>& a, const FallibleTArray<uint8_t>& b);

nsresult aes_encrypt(std::string_view plaintext, FallibleTArray<uint8_t>& outEncrypted);

nsresult aes_decrypt(const FallibleTArray<uint8_t>& encryptedData, nsACString& outPlaintext);

}