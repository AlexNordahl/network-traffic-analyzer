#ifndef DNS_HEADER_H
#define DNS_HEADER_H

#include <arpa/inet.h>
#include <netinet/ether.h>

#include <string>

struct DnsHeader
{
    uint16_t id;
    uint16_t flags;
    uint16_t qcount;
    uint16_t ancount;
    uint16_t aucount;
    uint16_t adcount;

    int getId() const { return ntohs(id); };
    int getFlags() const { return ntohs(flags); };
    int getQuestionCount() const { return ntohs(qcount); };
    int getAnswerCount() const { return ntohs(ancount); };
    int getAuthCount() const { return ntohs(aucount); };
    int getAdditionalCount() const { return ntohs(adcount); };
};

#endif