#ifndef COLORS_H
#define COLORS_H

namespace ansi
{
inline constexpr const char* black = "\033[0;30m";
inline constexpr const char* red = "\033[0;31m";
inline constexpr const char* green = "\033[0;32m";
inline constexpr const char* yellow = "\033[0;33m";
inline constexpr const char* blue = "\033[0;34m";
inline constexpr const char* purple = "\033[0;35m";
inline constexpr const char* cyan = "\033[0;36m";
inline constexpr const char* white = "\033[0;37m";
inline constexpr const char* reset = "\033[0m";

inline constexpr const char* bright_red = "\033[91m";
inline constexpr const char* bright_green = "\033[92m";
inline constexpr const char* bright_yellow = "\033[93m";
inline constexpr const char* bright_blue = "\033[94m";
inline constexpr const char* bright_magenta = "\033[95m";
inline constexpr const char* bright_cyan = "\033[96m";

inline constexpr const char* bold = "\033[1m";
inline constexpr const char* dim = "\033[2m";
inline constexpr const char* underline = "\033[4m";
}  // namespace ansi

#endif