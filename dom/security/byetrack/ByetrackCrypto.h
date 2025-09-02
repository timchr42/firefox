#include "nsTArray.h"

namespace mozilla::byetrack {

nsresult hmac_sha256(std::string_view msg, FallibleTArray<uint8_t>& outHmac);

bool constantTimeEquals(const FallibleTArray<uint8_t>& a, const FallibleTArray<uint8_t>& b);

}