#ifndef DOM_SECURITY_BYETRACK_UTILS_BYETRACKLOGGING_H_
#define DOM_SECURITY_BYETRACK_UTILS_BYETRACKLOGGING_H_

#include "mozilla/glue/Debug.h"
#include "prenv.h"
#include "prprf.h"
#include <cstdarg>

namespace mozilla::byetrack {

// Centralized logging for Byetrack components
class ByetrackLogger {
public:
  enum class Component {
    CRYPTO,
    CODEC,
    PARSER,
    VALIDATOR,
    TEST
  };

  static void Log(Component component, const char* format, ...) {
    const char* prefix = GetPrefix(component);
    va_list args;
    va_start(args, format);
    printf_stderr("%s ", prefix);
    vprintf_stderr(format, args);
    printf_stderr("\n");
    va_end(args);
  }

  static void LogError(Component component, const char* format, ...) {
    const char* prefix = GetPrefix(component);
    va_list args;
    va_start(args, format);
    printf_stderr("%s ERROR: ", prefix);
    vprintf_stderr(format, args);
    printf_stderr("\n");
    va_end(args);
  }

  static void LogDebug(Component component, const char* format, ...) {
    // Only log debug messages if debug mode is enabled
    if (!IsDebugEnabled()) {
      return;
    }
    
    const char* prefix = GetPrefix(component);
    va_list args;
    va_start(args, format);
    printf_stderr("%s DEBUG: ", prefix);
    vprintf_stderr(format, args);
    printf_stderr("\n");
    va_end(args);
  }

private:
  static const char* GetPrefix(Component component) {
    switch (component) {
      case Component::CRYPTO:
        return "Byetrack (Crypto)";
      case Component::CODEC:
        return "Byetrack (Codec)";
      case Component::PARSER:
        return "Byetrack (Parser)";
      case Component::VALIDATOR:
        return "Byetrack (Validator)";
      case Component::TEST:
        return "Byetrack (Test)";
      default:
        return "Byetrack";
    }
  }

  static bool IsDebugEnabled() {
    static bool checked = false;
    static bool enabled = false;
    
    if (!checked) {
      enabled = PR_GetEnv("BYETRACK_DEBUG") != nullptr;
      checked = true;
    }
    
    return enabled;
  }
};

// Convenience macros
#define BYETRACK_LOG(component, ...) \
  mozilla::byetrack::ByetrackLogger::Log(mozilla::byetrack::ByetrackLogger::Component::component, __VA_ARGS__)

#define BYETRACK_LOG_ERROR(component, ...) \
  mozilla::byetrack::ByetrackLogger::LogError(mozilla::byetrack::ByetrackLogger::Component::component, __VA_ARGS__)

#define BYETRACK_LOG_DEBUG(component, ...) \
  mozilla::byetrack::ByetrackLogger::LogDebug(mozilla::byetrack::ByetrackLogger::Component::component, __VA_ARGS__)

} // namespace mozilla::byetrack

#endif // DOM_SECURITY_BYETRACK_UTILS_BYETRACKLOGGING_H_