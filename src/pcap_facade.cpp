#include "pcap_facade.h"

PcapFacade::PcapFacade()
{
    pcap_findalldevs(&allDevs, errbuf);
}

PcapFacade::~PcapFacade()
{
    pcap_freealldevs(allDevs);
    if (handle != nullptr)
        pcap_close(handle);
}

void PcapFacade::selectDevice(const std::string_view devName)
{
    for (auto d = allDevs; d != nullptr; d = d->next)
    {
        if (strcmp(d->name, devName.data()) == 0)
        {
            selectedDevName = devName;
            selectedDev = d;
            extractIPv4Data();
            return;
        }
    }

    throw std::runtime_error("selectDevice(): device not found");
}

void PcapFacade::autoSelectDevice()
{
    selectedDevName = allDevs->name;
    selectedDev = allDevs;
    extractIPv4Data();
}

void PcapFacade::configure(int snaplen, bool promisc, int timeoutMs)
{
    if (selectedDevName.empty())
        throw std::runtime_error("configure(): device not selected");

    handle = pcap_create(selectedDevName.c_str(), errbuf);

    if (handle == nullptr)
        throw std::runtime_error("configure(): " + std::string(errbuf));

    if (pcap_set_snaplen(handle, snaplen) < 0)
        throw std::runtime_error("configure(): snaplen error");

    if (pcap_set_promisc(handle, promisc) < 0)
        throw std::runtime_error("configure(): promisc error");

    if (pcap_set_timeout(handle, timeoutMs) < 0)
        throw std::runtime_error("configure(): timeoutMs error");
}

void PcapFacade::activate()
{
    if (handle == nullptr)
        throw std::runtime_error("activate(): handle is null, configure probably not set");

    int code = pcap_activate(handle);

    if (code < 0)
    {
        if (code == PCAP_ERROR_PERM_DENIED)
            throw std::runtime_error("activate(): permission denied, try running as root");
        pcap_close(handle);
        handle = nullptr;
        throw std::runtime_error("activate(): pcap_activate error");
    }
}

std::string PcapFacade::getSelectedDevice() const { return selectedDevName; }

std::string PcapFacade::getIPv4() const { return ipv4; }

std::string PcapFacade::getMask() const { return mask; }

[[nodiscard]] std::vector<std::string> PcapFacade::listAllDevices() const
{
    std::vector<std::string> result{};
    for (auto d = allDevs; d != nullptr; d = d->next)
        result.push_back(d->name);

    return result;
}

int PcapFacade::maskToCIDR(const std::string& mask) const
{
    std::string temp {mask};
    temp.resize(15, '0');
    temp += '.';
    
    int count = 0;
    int ptr1 = 0;
    int ptr2 = 4;
    while (ptr2 < temp.length())
    {
        int octet = std::stoi(temp.substr(ptr1, ptr2));
        ptr1 = ptr2;
        ptr2 += 4;

        while (octet) 
        {
            count += octet & 1;
            octet >>= 1;
        }
    }

    return count;
}

std::pair<EtherFrame, const u_char*> PcapFacade::next()
{
    pcap_pkthdr *hdr;
    const u_char *bytes;

    int res = pcap_next_ex(handle, &hdr, &bytes);

    if (res <= 0)
        return {};

    struct ether_header* eptr;
    eptr = (struct ether_header*) bytes;

    EtherFrame frame;
    frame.payloadLen = hdr->caplen - sizeof(ether_header);;
    memcpy(frame.source, eptr->ether_shost, 6);
    memcpy(frame.destination, eptr->ether_dhost, 6);
    frame.type = ntohs(eptr->ether_type);

    const u_char* payload = bytes + sizeof(ether_header);

    return {frame, payload};
}

std::pair<IpHeader, const u_char*> PcapFacade::parseIPV4(const u_char* payload)
{
    IpHeader ip{};
    std::memcpy(&ip, payload, sizeof(IpHeader));

    uint8_t ihl = ip.ver_ihl & 0x0F;
    size_t headerLength = ihl * 4;

    const u_char* data = payload + headerLength;

    return {ip, data};
}

TcpHeader PcapFacade::parseTCP(const u_char* data)
{
    TcpHeader tcp {};
    std::memcpy(&tcp, data, sizeof(tcp));

    tcp.srcPort = ntohs(tcp.srcPort);
    tcp.dstPort = ntohs(tcp.dstPort);
    tcp.seqNumber = ntohl(tcp.seqNumber);
    tcp.ackNumber = ntohl(tcp.ackNumber);
    tcp.windowSize = ntohs(tcp.windowSize);
    tcp.checksum = ntohs(tcp.checksum);
    tcp.urg_pointer= ntohs(tcp.urg_pointer);

    return tcp;
}

ArpHeader PcapFacade::parseARP(const u_char* payload)
{
    ArpHeader arp{};
    memcpy(&arp, payload, sizeof(ArpHeader));
    return arp;
}

void PcapFacade::extractIPv4Data()
{
    struct in_addr addr;
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    pcap_lookupnet(selectedDevName.c_str(), &netp, &maskp, errbuf);

    addr.s_addr = netp;
    ipv4 = inet_ntoa(addr);

    addr.s_addr = maskp;
    mask = inet_ntoa(addr);
}
