#ifndef DOM_SECURITY_BYETRACK_CODEC_BYETRACKTOKENPARSER_H_
#define DOM_SECURITY_BYETRACK_CODEC_BYETRACKTOKENPARSER_H_

#include "nsTArray.h"
#include "nsError.h"
#include "core/ByetrackToken.h"

namespace mozilla::byetrack {

/**
 * Handles JSON parsing for Byetrack tokens.
 * Separates JSON parsing logic from the main codec functionality.
 */
class TokenParser {
public:
  /**
   * Parse a JSON blob containing an array of token strings
   */
  static nsresult ParseTokenBlob(const nsACString& aBlob,
                                nsTArray<nsCString>& outTokenStrings);

  /**
   * Parse a single token from decoded JSON string 
   */
  static nsresult ParseSingleToken(const nsACString& aDecodedJsonString,
                                  ByetrackToken& outToken);

private:
  TokenParser() = delete;
  ~TokenParser() = delete;
  TokenParser(const TokenParser&) = delete;
  TokenParser& operator=(const TokenParser&) = delete;
};

} // namespace mozilla::byetrack

#endif // DOM_SECURITY_BYETRACK_CODEC_BYETRACKTOKENPARSER_H_