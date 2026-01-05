#include "pcap_facade.h"

PcapFacade::PcapFacade() { pcap_findalldevs(&allDevs, errbuf); }

PcapFacade::~PcapFacade()
{
    pcap_freealldevs(allDevs);
    if (handle != nullptr) pcap_close(handle);
    pcap_freecode(&fp);
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
        throw std::runtime_error(
            "activate(): handle is null, configure probably not set");

    int code = pcap_activate(handle);

    if (code < 0)
    {
        if (code == PCAP_ERROR_PERM_DENIED)
            throw std::runtime_error(
                "activate(): permission denied, try running as root");
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
    for (auto d = allDevs; d != nullptr; d = d->next) result.push_back(d->name);

    return result;
}

void PcapFacade::setFilter(std::string text, const bool optimize)
{
    if (pcap_compile(handle, &fp, text.c_str(), optimize, maskp) < 0)
    {
        throw std::runtime_error("setFilter(): pcap_compile error");
    }

    if (pcap_setfilter(handle, &fp) < 0)
    {
        pcap_freecode(&fp);
        throw std::runtime_error("setFilter(): pcap_setFilter error");
    }
}

std::pair<EtherFrame, const u_char*> PcapFacade::next()
{
    pcap_pkthdr* hdr;
    const u_char* bytes;

    int res = pcap_next_ex(handle, &hdr, &bytes);

    if (res < 0) throw std::runtime_error("next(): pcap_next_ex error");

    struct ether_header* eptr;
    eptr = (struct ether_header*)bytes;

    EtherFrame frame;
    frame.payloadLen = static_cast<int>(hdr->caplen - sizeof(ether_header));

    memcpy(frame.source, eptr->ether_shost, 6);
    memcpy(frame.destination, eptr->ether_dhost, 6);

    frame.type = ntohs(eptr->ether_type);

    const u_char* payload = bytes + sizeof(ether_header);

    return {frame, payload};
}

void PcapFacade::extractIPv4Data()
{
    struct in_addr addr;
    pcap_lookupnet(selectedDevName.c_str(), &netp, &maskp, errbuf);

    addr.s_addr = netp;
    ipv4 = inet_ntoa(addr);

    addr.s_addr = maskp;
    mask = inet_ntoa(addr);
}
