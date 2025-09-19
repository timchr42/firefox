#ifndef DOM_SECURITY_BYETRACK_CORE_BYETRACKCONSTANTS_H_
#define DOM_SECURITY_BYETRACK_CORE_BYETRACKCONSTANTS_H_

#include <cstddef>  // for size_t

namespace mozilla::byetrack {

// Cryptographic constants
namespace crypto {
  constexpr const char* SECRET_KEY = "super-secret-key";
  constexpr const char* AES_ALGORITHM = "AES/CBC/PKCS5Padding";
  constexpr const char* KEY_ALGORITHM = "AES";
  constexpr const char* HMAC_ALGORITHM = "HmacSHA256";
  constexpr size_t AES_IV_SIZE = 16;        // AES block size
  constexpr size_t AES_KEY_SIZE = 32;       // 256-bit key
  constexpr size_t HMAC_OUTPUT_SIZE = 32;   // SHA256 output size
}

// Token constants
namespace token {
  constexpr const char* WILDCARD_VALUE = "*";
  constexpr const char* DEFAULT_VERSION = "DEFAULT";
  constexpr const char* SEPARATOR = ".";
}

// Access rights constants
namespace access {
  constexpr const char* READ = "READ";
  constexpr const char* WRITE = "WRITE"; 
  constexpr const char* READ_WRITE = "READ_WRITE";
  constexpr const char* NONE = "NONE";
}

// JSON field names
namespace json {
  constexpr const char* ACCESS_RIGHTS = "access_rights";
  constexpr const char* APPLICATION_ID = "application_id";
  constexpr const char* COOKIE_NAME = "cookie_name";
  constexpr const char* COOKIE_VALUE = "cookie_value";
  constexpr const char* DESTINATION_DOMAIN = "destination_domain";
  constexpr const char* GLOBAL_JAR = "global_jar";
  constexpr const char* VERSION_NAME = "version_name";
}

// Logging prefixes
namespace logging {
  constexpr const char* CRYPTO_PREFIX = "Byetrack (Crypto)";
  constexpr const char* CODEC_PREFIX = "Byetrack (Codec)";
  constexpr const char* PARSER_PREFIX = "Byetrack (Parser)";
  constexpr const char* VALIDATOR_PREFIX = "Byetrack (Validator)";
  constexpr const char* TEST_PREFIX = "Byetrack (Test)";
}

} // namespace mozilla::byetrack

#endif // DOM_SECURITY_BYETRACK_CORE_BYETRACKCONSTANTS_H_