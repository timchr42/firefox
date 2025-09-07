#include "ByetrackTokens.h"

namespace mozilla::byetrack {
    nsresult getFinalTokensCookieHeader(const nsTArray<ByetrackToken>& finalTokens,
                                       nsACString& outHeader);

    nsresult parseTokenBlob(const nsACString& aBlob,
                           const nsACString& aDomainName,
                           const nsACString& aPackageName,
                           const nsACString& aVersionName,
                           nsTArray<ByetrackToken>& outTokens);

    nsresult decodeTokenString(const nsACString& encoded,
                              nsACString& decoded);

    nsresult encodeToken(const ByetrackToken& token,
                        nsACString& outEncoded);

    nsresult parseSingleToken(const nsACString& decodedJsonString,
                             ByetrackToken& outToken);

    nsresult validateTokenFields(const nsACString& expectedPackageName,
                                const nsACString& expectedVersionName,
                                const nsACString& expectedDomainName,
                                const ByetrackToken& token);

    // Test function to verify encode/decode roundtrip
    nsresult testEncodeDecodeRoundtrip();

} // namespace mozilla::byetrack