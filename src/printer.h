#ifndef PRINTER_H
#define PRINTER_H

#include "net_headers/ether_frame.h"
#include "net_headers/ip_header.h"
#include "net_headers/arp_header.h"
#include <iomanip>
#include <iostream>

void printEthernetFrame(const EtherFrame& frame);
void printIPV4(const IpHeader& header);

#endif