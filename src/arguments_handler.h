#ifndef ARGUMENTS_HANDLER_H
#define ARGUMENTS_HANDLER_H

#include <string>
#include <optional>
#include <cstring>
#include <array>
#include <algorithm>
#include <exception>
#include <stdexcept>
#include <string_view>

void validateArgv(int argc, const char* argv[]);
bool listDevicesArgument(int argc, const char* argv[]);
std::optional<std::string> selectDeviceArgument(int argc, const char* argv[]);
std::optional<std::string> filterArgument(int argc, const char* argv[]);

#endif