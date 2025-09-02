#include "ByetrackCrypto.h"
#include <nss.h>
#include <pk11pub.h>
#include <secitem.h>
#include <cstdint>
#include <string_view>

namespace mozilla::byetrack {

static const char* SECRET_KEY = "super-secret-key";

nsresult hmac_sha256(std::string_view msg, FallibleTArray<uint8_t>& outHmac) {
    // In Gecko, NSS is already initialized. Otherwise call NSS_NoDB_Init(NULL).
    SECItem keyItem;
    keyItem.type = siBuffer;
    keyItem.data = (unsigned char*)SECRET_KEY;
    keyItem.len  = (unsigned int)strlen(SECRET_KEY);

    PK11SlotInfo* slot = PK11_GetInternalSlot();
    if (!slot) {
        return NS_ERROR_FAILURE;
    }

    PK11SymKey* sym = PK11_ImportSymKey(slot, CKM_SHA256_HMAC, PK11_OriginUnwrap,
                                        CKA_SIGN, &keyItem, nullptr);
    if (!sym) {
        PK11_FreeSlot(slot);
        return NS_ERROR_FAILURE;
    }

    PK11Context* ctx = PK11_CreateContextBySymKey(CKM_SHA256_HMAC, CKA_SIGN, sym, nullptr);
    if (!ctx) {
        PK11_FreeSymKey(sym);
        PK11_FreeSlot(slot);
        return NS_ERROR_FAILURE;
    }

    SECStatus rv = PK11_DigestBegin(ctx);
    if (rv != SECSuccess) {
        PK11_DestroyContext(ctx, PR_TRUE);
        PK11_FreeSymKey(sym);
        PK11_FreeSlot(slot);
        return NS_ERROR_FAILURE;
    }

    rv = PK11_DigestOp(ctx, reinterpret_cast<const unsigned char*>(msg.data()), msg.size());
    if (rv != SECSuccess) {
        PK11_DestroyContext(ctx, PR_TRUE);
        PK11_FreeSymKey(sym);
        PK11_FreeSlot(slot);
        return NS_ERROR_FAILURE;
    }

    unsigned char out[32];
    unsigned int out_len = 0;
    rv = PK11_DigestFinal(ctx, out, &out_len, sizeof(out));

    PK11_DestroyContext(ctx, PR_TRUE);
    PK11_FreeSymKey(sym);
    PK11_FreeSlot(slot);

    if (rv != SECSuccess) {
        return NS_ERROR_FAILURE;
    }

    // Copy to FallibleTArray
    if (!outHmac.SetLength(out_len, fallible)) {
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