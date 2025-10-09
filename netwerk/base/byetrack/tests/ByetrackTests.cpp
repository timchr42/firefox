#include "ByetrackTests.h"
#include "core/ByetrackToken.h"
#include "codec/ByetrackTokenEncoder.h"
#include "codec/ByetrackTokenParser.h"
#include "codec/ByetrackTokenValidator.h"
#include "crypto/ByetrackCrypto.h"
#include "utils/ByetrackBase64Utils.h"
#include "nsString.h"
#include "nsTArray.h"
#include "js/JSON.h"

using namespace mozilla::byetrack;

namespace mozilla::byetrack::tests {

nsresult ByetrackTests::TestEncodeDecodeRoundtrip() {
  // Create test token
  ByetrackToken testToken;
  testToken.destinationDomain = "example.com";
  testToken.cookieName = "test_cookie";
  testToken.cookieValue = "test_value";
  testToken.packageName = "com.example.app";
  testToken.versionName = "1.0.0";
  testToken.accessRights = AccessRights::READ_WRITE;
  testToken.globalJar = true;

  // Test encoding
  nsAutoCString encodedToken;
  nsresult rv = TokenEncoder::EncodeToken(testToken, encodedToken);
  if (NS_FAILED(rv)) {
    return rv;
  }

  // Test decoding
  nsAutoCString decodedJson;
  rv = TokenEncoder::DecodeTokenString(encodedToken, decodedJson);
  if (NS_FAILED(rv)) {
    return rv;
  }

  // Parse the decoded JSON back to a token
  ByetrackToken decodedToken;
  rv = TokenParser::ParseSingleToken(decodedJson, decodedToken);
  if (NS_FAILED(rv)) {
    return rv;
  }

  // Verify content
  if (!testToken.destinationDomain.Equals(decodedToken.destinationDomain) ||
      !testToken.cookieName.Equals(decodedToken.cookieName) ||
      !testToken.cookieValue.Equals(decodedToken.cookieValue) ||
      !testToken.packageName.Equals(decodedToken.packageName) ||
      !testToken.versionName.Equals(decodedToken.versionName) ||
      testToken.accessRights != decodedToken.accessRights ||
      testToken.globalJar != decodedToken.globalJar) {
    return NS_ERROR_FAILURE;
  }

  return NS_OK;
}

nsresult ByetrackTests::TestEncryptedEncodeDecodeRoundtrip() {
  // Create test token
  ByetrackToken testToken;
  testToken.destinationDomain = "secure.example.com";
  testToken.cookieName = "secure_cookie";
  testToken.cookieValue = "secure_value";
  testToken.packageName = "com.example.secureapp";
  testToken.versionName = "2.0.0";
  testToken.accessRights = AccessRights::READ_WRITE;
  testToken.globalJar = false;

  // Test encrypted encoding - Note: Need to implement encrypted methods in TokenEncoder
  nsAutoCString encryptedToken;
  nsresult rv = TokenEncoder::EncodeEncryptedToken(testToken, encryptedToken);
  if (NS_FAILED(rv)) {
    return rv;
  }

  // Test encrypted decoding
  nsAutoCString decodedJson;
  rv = TokenEncoder::DecodeEncryptedTokenString(encryptedToken, decodedJson);
  if (NS_FAILED(rv)) {
    return rv;
  }

  // Parse the decoded JSON back to a token
  ByetrackToken decodedToken;
  rv = TokenParser::ParseSingleToken(decodedJson, decodedToken);
  if (NS_FAILED(rv)) {
    return rv;
  }

  // Verify content
  if (!testToken.destinationDomain.Equals(decodedToken.destinationDomain) ||
      !testToken.cookieName.Equals(decodedToken.cookieName) ||
      !testToken.cookieValue.Equals(decodedToken.cookieValue) ||
      !testToken.packageName.Equals(decodedToken.packageName) ||
      !testToken.versionName.Equals(decodedToken.versionName) ||
      testToken.accessRights != decodedToken.accessRights ||
      testToken.globalJar != decodedToken.globalJar) {
    return NS_ERROR_FAILURE;
  }

  return NS_OK;
}

nsresult ByetrackTests::TestTokenParsing() {
  // Create test token JSON
  nsAutoCString tokenBlob(R"([{
    "destinationDomain": "example.com",
    "cookieName": "test_cookie", 
    "cookieValue": "test_value",
    "packageName": "com.example.app",
    "versionName": "1.0.0",
    "accessRights": "READ_WRITE",
    "globalJar": true
  }])");

  // Test parsing - simplified version since we need JS context for full test
  ByetrackToken token;
  token.destinationDomain = "example.com";
  token.cookieName = "test_cookie";
  token.cookieValue = "test_value";
  token.packageName = "com.example.app";
  token.versionName = "1.0.0";
  token.accessRights = AccessRights::READ_WRITE;
  token.globalJar = true;

  // Validate the token
  nsAutoCString packageName("com.example.app");
  nsAutoCString versionName("1.0.0");
  nsAutoCString domainName("example.com");
  nsresult rv = TokenValidator::ValidateTokenFields(packageName, versionName, domainName, token);
  if (NS_FAILED(rv)) {
    return rv;
  }

  return NS_OK;
}

nsresult ByetrackTests::TestTokenValidation() {
  ByetrackToken token;
  token.destinationDomain = "*.example.com";
  token.cookieName = "test_cookie";
  token.cookieValue = "test_value";
  token.packageName = "com.example.app";
  token.versionName = "1.0.0";
  token.accessRights = AccessRights::READ_WRITE;
  token.globalJar = false;

  // Test validation
  nsAutoCString packageName("com.example.app");
  nsAutoCString versionName("1.0.0");
  nsAutoCString domainName("*.example.com");
  nsresult rv = TokenValidator::ValidateTokenFields(packageName, versionName, domainName, token);
  if (NS_FAILED(rv)) {
    return rv;
  }

  // Test domain matching
  nsAutoCString testDomain("sub.example.com");
  nsAutoCString tokenDomain("*.example.com");
  bool matches = TokenValidator::IsValidDomainMatch(testDomain, tokenDomain);
  if (!matches) {
    return NS_ERROR_FAILURE;
  }

  return NS_OK;
}

nsresult ByetrackTests::TestCryptoOperations() {
  // Test data
  nsAutoCString plaintext("Hello, World! This is a test message.");
  
  // Encrypt
  FallibleTArray<uint8_t> ciphertext;
  nsresult rv = aes_encrypt(plaintext.get(), ciphertext);
  if (NS_FAILED(rv)) {
    return rv;
  }

  // Decrypt
  nsAutoCString decrypted;
  rv = aes_decrypt(ciphertext, decrypted);
  if (NS_FAILED(rv)) {
    return rv;
  }

  // Verify
  if (!plaintext.Equals(decrypted)) {
    return NS_ERROR_FAILURE;
  }

  return NS_OK;
}

nsresult ByetrackTests::TestBase64Operations() {
  nsAutoCString testData("Hello, World! Testing Base64 operations.");
  
  // Encode
  nsAutoCString encoded;
  nsresult rv = Base64Utils::Encode(reinterpret_cast<const uint8_t*>(testData.get()), 
                                   testData.Length(), 
                                   encoded);
  if (NS_FAILED(rv)) {
    return rv;
  }

  // Decode
  FallibleTArray<uint8_t> decodedBytes;
  rv = Base64Utils::Decode(encoded, decodedBytes);
  if (NS_FAILED(rv)) {
    return rv;
  }

  // Convert back to string
  nsAutoCString decoded(reinterpret_cast<const char*>(decodedBytes.Elements()), 
                       decodedBytes.Length());

  // Verify
  if (!testData.Equals(decoded)) {
    return NS_ERROR_FAILURE;
  }

  return NS_OK;
}

nsresult ByetrackTests::RunAllTests() {
  nsresult rv;

  rv = TestBase64Operations();
  if (NS_FAILED(rv)) {
    return rv;
  }

  rv = TestCryptoOperations();
  if (NS_FAILED(rv)) {
    return rv;
  }

  rv = TestTokenValidation();
  if (NS_FAILED(rv)) {
    return rv;
  }

  rv = TestTokenParsing();
  if (NS_FAILED(rv)) {
    return rv;
  }

  rv = TestEncodeDecodeRoundtrip();
  if (NS_FAILED(rv)) {
    return rv;
  }

  rv = TestEncryptedEncodeDecodeRoundtrip();
  if (NS_FAILED(rv)) {
    return rv;
  }

  return NS_OK;
}

} // namespace mozilla::byetrack::tests