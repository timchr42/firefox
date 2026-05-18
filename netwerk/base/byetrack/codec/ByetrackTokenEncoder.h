#ifndef DOM_SECURITY_BYETRACK_CODEC_BYETRACKTOKENENCODER_H_
#define DOM_SECURITY_BYETRACK_CODEC_BYETRACKTOKENENCODER_H_

#include "nsError.h"
#include "mozilla/byetrack/core/ByetrackToken.h"

namespace mozilla::byetrack {

/**
 * Handles token encoding and decoding operations.
 * Centralizes all token serialization/deserialization logic.
 */
class TokenEncoder {
public:
  /**
   * Encode a token to its standard format (base64url(JSON) + "." + signature)
   */
  static nsresult EncodeToken(const ByetrackToken& aToken,
                             nsACString& aOutEncodedToken);

  /**
   * Encode a token to encrypted format (AES encrypted + base64url encoded)
   */
  static nsresult EncodeEncryptedToken(const ByetrackToken& aToken,
                                      nsACString& aOutEncryptedToken);

  /**
   * Decode a standard token string to JSON payload
   */
  static nsresult DecodeTokenString(const nsACString& aEncodedToken,
                                   nsACString& aOutDecodedJson);

  /**
   * Decode an encrypted token string to JSON payload
   */
  static nsresult DecodeEncryptedTokenString(const nsACString& aEncryptedToken,
                                            nsACString& aOutDecodedJson);

  /**
   * Generate cookie header from a list of tokens
   */
  static nsresult GetCookieHeader(const nsTArray<ByetrackToken>& aTokens,
                                 nsACString& aOutHeader);

private:
  /**
   * Convert token to JSON string for signing/encryption
   */
  static nsresult TokenToJson(const ByetrackToken& aToken,
                             nsACString& aOutJson);

  TokenEncoder() = delete;
  ~TokenEncoder() = delete;
  TokenEncoder(const TokenEncoder&) = delete;
  TokenEncoder& operator=(const TokenEncoder&) = delete;
};

} // namespace mozilla::byetrack

#endif // DOM_SECURITY_BYETRACK_CODEC_BYETRACKTOKENENCODER_H_
