#include "ByetrackCrypto.h"
#include "core/ByetrackConstants.h"
#include <nss.h>
#include <pk11pub.h>
#include <secitem.h>
#include <sechash.h>
#include <cstdint>
#include <string_view>

namespace mozilla::byetrack {

static const char* SECRET_KEY = crypto::SECRET_KEY;

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

nsresult deriveAESKey(FallibleTArray<uint8_t>& outKey) {
    // Derive 256-bit AES key from SECRET_KEY using SHA-256
    SECStatus rv = HASH_HashBuf(HASH_AlgSHA256,
                                outKey.Elements(),
                                reinterpret_cast<const unsigned char*>(SECRET_KEY),
                                strlen(SECRET_KEY));

    if (rv != SECSuccess) {
        printf_stderr("Byetrack (Crypto) Failed to derive AES key\n");
        return NS_ERROR_FAILURE;
    }

    return NS_OK;
}

nsresult aes_encrypt(std::string_view plaintext, FallibleTArray<uint8_t>& outEncrypted) {
    // Allocate space for 32-byte key
    FallibleTArray<uint8_t> keyBytes;
    if (!keyBytes.SetLength(32, fallible)) {
        return NS_ERROR_OUT_OF_MEMORY;
    }
    
    nsresult rv = deriveAESKey(keyBytes);
    if (NS_FAILED(rv)) {
        return rv;
    }
    
    // Generate random 16-byte IV
    unsigned char iv[16];
    SECStatus secRv = PK11_GenerateRandom(iv, sizeof(iv));
    if (secRv != SECSuccess) {
        printf_stderr("Byetrack (Crypto) Failed to generate random IV\n");
        return NS_ERROR_FAILURE;
    }
    
    // Get slot and import the key
    PK11SlotInfo* slot = PK11_GetInternalSlot();
    if (!slot) {
        printf_stderr("Byetrack (Crypto) Failed to get internal slot\n");
        return NS_ERROR_FAILURE;
    }
    
    SECItem keyItem;
    keyItem.type = siBuffer;
    keyItem.data = keyBytes.Elements();
    keyItem.len = keyBytes.Length();
    
    PK11SymKey* symKey = PK11_ImportSymKey(slot, CKM_AES_CBC, PK11_OriginUnwrap,
                                          CKA_ENCRYPT, &keyItem, nullptr);
    if (!symKey) {
        printf_stderr("Byetrack (Crypto) Failed to import AES key\n");
        PK11_FreeSlot(slot);
        return NS_ERROR_FAILURE;
    }
    
    // Set up IV parameter
    SECItem ivItem;
    ivItem.type = siBuffer;
    ivItem.data = iv;
    ivItem.len = sizeof(iv);
    
    // Create encryption context
    PK11Context* ctx = PK11_CreateContextBySymKey(CKM_AES_CBC_PAD, CKA_ENCRYPT, symKey, &ivItem);
    if (!ctx) {
        printf_stderr("Byetrack (Crypto) Failed to create AES context\n");
        PK11_FreeSymKey(symKey);
        PK11_FreeSlot(slot);
        return NS_ERROR_FAILURE;
    }
    
    // Calculate output buffer size (input + padding + IV)
    unsigned int maxOutLen = plaintext.size() + 16 + 16; // AES block size + IV
    FallibleTArray<uint8_t> encrypted;
    if (!encrypted.SetLength(maxOutLen, fallible)) {
        PK11_DestroyContext(ctx, PR_TRUE);
        PK11_FreeSymKey(symKey);
        PK11_FreeSlot(slot);
        return NS_ERROR_OUT_OF_MEMORY;
    }
    
    // Encrypt the data
    int outLen = 0;
    secRv = PK11_CipherOp(ctx, encrypted.Elements(), &outLen, static_cast<int>(maxOutLen),
                         reinterpret_cast<const unsigned char*>(plaintext.data()), 
                         static_cast<int>(plaintext.size()));
    
    if (secRv != SECSuccess) {
        printf_stderr("Byetrack (Crypto) Failed to encrypt data\n");
        PK11_DestroyContext(ctx, PR_TRUE);
        PK11_FreeSymKey(symKey);
        PK11_FreeSlot(slot);
        return NS_ERROR_FAILURE;
    }
    
    // Finalize encryption
    unsigned int finalLen = 0;
    secRv = PK11_DigestFinal(ctx, encrypted.Elements() + outLen, &finalLen, 
                            maxOutLen - outLen);
    
    PK11_DestroyContext(ctx, PR_TRUE);
    PK11_FreeSymKey(symKey);
    PK11_FreeSlot(slot);
    
    if (secRv != SECSuccess) {
        printf_stderr("Byetrack (Crypto) Failed to finalize encryption\n");
        return NS_ERROR_FAILURE;
    }
    
    unsigned int totalEncryptedLen = outLen + finalLen;
    
    // Prepare output: IV + encrypted data
    if (!outEncrypted.SetLength(16 + totalEncryptedLen, fallible)) {
        return NS_ERROR_OUT_OF_MEMORY;
    }
    
    // Copy IV first, then encrypted data
    memcpy(outEncrypted.Elements(), iv, 16);
    memcpy(outEncrypted.Elements() + 16, encrypted.Elements(), totalEncryptedLen);
    
    return NS_OK;
}

nsresult aes_decrypt(const FallibleTArray<uint8_t>& encryptedData, nsACString& outPlaintext) {
    if (encryptedData.Length() < 16) {
        printf_stderr("Byetrack (Crypto) Invalid encrypted data length\n");
        return NS_ERROR_INVALID_ARG;
    }
    
    // Extract IV and encrypted data
    const unsigned char* iv = encryptedData.Elements();
    const unsigned char* encrypted = encryptedData.Elements() + 16;
    unsigned int encryptedLen = encryptedData.Length() - 16;
    
    // Derive the same key
    FallibleTArray<uint8_t> keyBytes;
    if (!keyBytes.SetLength(32, fallible)) {
        return NS_ERROR_OUT_OF_MEMORY;
    }
    
    nsresult rv = deriveAESKey(keyBytes);
    if (NS_FAILED(rv)) {
        return rv;
    }
    
    // Get slot and import the key
    PK11SlotInfo* slot = PK11_GetInternalSlot();
    if (!slot) {
        printf_stderr("Byetrack (Crypto) Failed to get internal slot\n");
        return NS_ERROR_FAILURE;
    }
    
    SECItem keyItem;
    keyItem.type = siBuffer;
    keyItem.data = keyBytes.Elements();
    keyItem.len = keyBytes.Length();
    
    PK11SymKey* symKey = PK11_ImportSymKey(slot, CKM_AES_CBC, PK11_OriginUnwrap,
                                          CKA_DECRYPT, &keyItem, nullptr);
    if (!symKey) {
        printf_stderr("Byetrack (Crypto) Failed to import AES key for decryption\n");
        PK11_FreeSlot(slot);
        return NS_ERROR_FAILURE;
    }
    
    // Set up IV parameter
    SECItem ivItem;
    ivItem.type = siBuffer;
    ivItem.data = const_cast<unsigned char*>(iv);
    ivItem.len = 16;
    
    // Create decryption context
    PK11Context* ctx = PK11_CreateContextBySymKey(CKM_AES_CBC_PAD, CKA_DECRYPT, symKey, &ivItem);
    if (!ctx) {
        printf_stderr("Byetrack (Crypto) Failed to create AES decryption context\n");
        PK11_FreeSymKey(symKey);
        PK11_FreeSlot(slot);
        return NS_ERROR_FAILURE;
    }
    
    // Decrypt the data
    FallibleTArray<uint8_t> decrypted;
    if (!decrypted.SetLength(encryptedLen + 16, fallible)) { // Extra space for padding
        PK11_DestroyContext(ctx, PR_TRUE);
        PK11_FreeSymKey(symKey);
        PK11_FreeSlot(slot);
        return NS_ERROR_OUT_OF_MEMORY;
    }
    
    int outLen = 0;
    SECStatus secRv = PK11_CipherOp(ctx, decrypted.Elements(), &outLen, 
                                   static_cast<int>(decrypted.Length()), 
                                   encrypted, static_cast<int>(encryptedLen));
    
    if (secRv != SECSuccess) {
        printf_stderr("Byetrack (Crypto) Failed to decrypt data\n");
        PK11_DestroyContext(ctx, PR_TRUE);
        PK11_FreeSymKey(symKey);
        PK11_FreeSlot(slot);
        return NS_ERROR_FAILURE;
    }
    
    // Finalize decryption
    unsigned int finalLen = 0;
    secRv = PK11_DigestFinal(ctx, decrypted.Elements() + outLen, &finalLen, 
                            decrypted.Length() - outLen);
    
    PK11_DestroyContext(ctx, PR_TRUE);
    PK11_FreeSymKey(symKey);
    PK11_FreeSlot(slot);
    
    if (secRv != SECSuccess) {
        printf_stderr("Byetrack (Crypto) Failed to finalize decryption\n");
        return NS_ERROR_FAILURE;
    }
    
    unsigned int totalDecryptedLen = outLen + finalLen;
    
    // Convert to string
    if (!outPlaintext.Assign(reinterpret_cast<const char*>(decrypted.Elements()), 
                            totalDecryptedLen, mozilla::fallible)) {
        return NS_ERROR_OUT_OF_MEMORY;
    }
    
    return NS_OK;
}

} // namespace mozilla::byetrack