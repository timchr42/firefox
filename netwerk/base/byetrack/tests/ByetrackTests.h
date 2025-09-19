#ifndef DOM_SECURITY_BYETRACK_TESTS_BYETRACKTESTS_H_
#define DOM_SECURITY_BYETRACK_TESTS_BYETRACKTESTS_H_

#include "nsError.h"

namespace mozilla::byetrack::tests {

/**
 * Test suite for Byetrack token system.
 * All test functions are centralized here for better organization.
 */
class ByetrackTests {
public:
  /**
   * Test standard encode/decode roundtrip
   */
  static nsresult TestEncodeDecodeRoundtrip();

  /**
   * Test encrypted encode/decode roundtrip
   */
  static nsresult TestEncryptedEncodeDecodeRoundtrip();

  /**
   * Test token parsing functionality
   */
  static nsresult TestTokenParsing();

  /**
   * Test token validation functionality
   */
  static nsresult TestTokenValidation();

  /**
   * Test crypto operations
   */
  static nsresult TestCryptoOperations();

  /**
   * Test Base64 utilities
   */
  static nsresult TestBase64Operations();

  /**
   * Run all tests
   */
  static nsresult RunAllTests();

private:
  ByetrackTests() = delete;
  ~ByetrackTests() = delete;
  ByetrackTests(const ByetrackTests&) = delete;
  ByetrackTests& operator=(const ByetrackTests&) = delete;
};

} // namespace mozilla::byetrack::tests

// Legacy compatibility for existing code
namespace mozilla::byetrack {
  using namespace tests;
  
  // Keep old function names
  inline nsresult testEncodeDecodeRoundtrip() {
    return ByetrackTests::TestEncodeDecodeRoundtrip();
  }
  
  inline nsresult testEncryptedEncodeDecodeRoundtrip() {
    return ByetrackTests::TestEncryptedEncodeDecodeRoundtrip();
  }
}

#endif // DOM_SECURITY_BYETRACK_TESTS_BYETRACKTESTS_H_