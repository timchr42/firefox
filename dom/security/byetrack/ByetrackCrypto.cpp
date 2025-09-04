#include "ByetrackCrypto.h"
#include <nss.h>
#include <pk11pub.h>
#include <secitem.h>
#include <cstdint>
#include <string_view>

namespace mozilla::byetrack {

static const char* SECRET_KEY = "super-secret-key";

nsresult hmac_sha256(std::string_view msg, FallibleTArray<uint8_t>& outHmac) {
    SECItem keyItem;
    keyItem.type = siBuffer;
    keyItem.data = (unsigned char*)SECRET_KEY;
    keyItem.len  = (unsigned int)strlen(SECRET_KEY);

    PK11SlotInfo* slot = PK11_GetInternalSlot();
    if (!slot) {
        printf_stderr("Byetrack (Crypto) Failed to get internal slot\n");
        return NS_ERROR_FAILURE;
    }

    // Import key for HMAC
    PK11SymKey* sym = PK11_ImportSymKey(slot, CKM_SHA256_HMAC, PK11_OriginUnwrap,
                                        CKA_SIGN, &keyItem, nullptr);
    if (!sym) {
        printf_stderr("Byetrack (Crypto) Failed to import symmetric key\n");
        PK11_FreeSlot(slot);
        return NS_ERROR_FAILURE;
    }

    // Create HMAC context with empty parameter
    SECItem noParam = { siBuffer, nullptr, 0 };
    PK11Context* ctx = PK11_CreateContextBySymKey(CKM_SHA256_HMAC, CKA_SIGN, sym, &noParam);
    if (!ctx) {
        printf_stderr("Byetrack (Crypto) Failed to create context\n");
        PK11_FreeSymKey(sym);
        PK11_FreeSlot(slot);
        return NS_ERROR_FAILURE;
    }

    // Begin HMAC operation
    SECStatus rv = PK11_DigestBegin(ctx);
    if (rv != SECSuccess) {
        printf_stderr("Byetrack (Crypto) Failed to begin digest\n");
        PK11_DestroyContext(ctx, PR_TRUE);
        PK11_FreeSymKey(sym);
        PK11_FreeSlot(slot);
        return NS_ERROR_FAILURE;
    }

    // Process the message
    rv = PK11_DigestOp(ctx, reinterpret_cast<const unsigned char*>(msg.data()), msg.size());
    if (rv != SECSuccess) {
        printf_stderr("Byetrack (Crypto) Failed to process digest operation\n");
        PK11_DestroyContext(ctx, PR_TRUE);
        PK11_FreeSymKey(sym);
        PK11_FreeSlot(slot);
        return NS_ERROR_FAILURE;
    }

    // Finalize and get result
    unsigned char out[32];  // SHA256 HMAC produces 32 bytes
    unsigned int out_len = 0;
    rv = PK11_DigestFinal(ctx, out, &out_len, sizeof(out));

    PK11_DestroyContext(ctx, PR_TRUE);
    PK11_FreeSymKey(sym);
    PK11_FreeSlot(slot);

    if (rv != SECSuccess) {
        printf_stderr("Byetrack (Crypto) Failed to finalize digest\n");
        return NS_ERROR_FAILURE;
    }

    // Copy to FallibleTArray
    if (!outHmac.SetLength(out_len, fallible)) {
        printf_stderr("Byetrack (Crypto) Failed to allocate output array\n");
        return NS_ERROR_OUT_OF_MEMORY;
    }

    memcpy(outHmac.Elements(), out, out_len);
    return NS_OK;
}

bool constantTimeEquals(const FallibleTArray<uint8_t>& a, const FallibleTArray<uint8_t>& b) {
    if (a.Length() != b.Length()) {
        return false;
    }
    bool equal = true;
    for (size_t i = 0; i < a.Length(); ++i) {
        if (a[i] != b[i]) {
            equal = false;
        }
    }
    return equal;
}

} // namespace mozilla::byetrack