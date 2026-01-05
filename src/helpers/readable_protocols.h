#ifndef READABLE_PROTOCOLS_H
#define READABLE_PROTOCOLS_H

#include <arpa/inet.h>

#include <array>
#include <bitset>
#include <string>
#include <vector>

std::string protocolKeyword(const int decimal);
std::string arpOperation(const int decimal);
std::vector<std::string> tcpFlags(const unsigned long long decimal);
std::vector<std::string> dnsFlags(const unsigned long long decimal);

#endif