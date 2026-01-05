#ifndef ARGUMENTS_HANDLER_H
#define ARGUMENTS_HANDLER_H

#include <algorithm>
#include <array>
#include <cstring>
#include <exception>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

#include "helpers/parsers.h"
#include "pcap_facade/pcap_facade.h"
#include "printer/console_printer.h"
#include "printer/file_printer.h"

void validateArgv(int argc, const char* argv[]);
bool listDevicesArgument(int argc, const char* argv[]);
std::optional<std::string> selectDeviceArgument(int argc, const char* argv[]);
std::optional<std::string> filterArgument(int argc, const char* argv[]);
void parseAndPrint(const EtherFrame& frame, const u_char* payload,
                   const Printer& pr);

#endif