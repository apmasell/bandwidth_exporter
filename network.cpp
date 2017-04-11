#include "bandwidth_exporter.hpp"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#define RETRY_THRESHOLD 10000

struct vlan_header {
  uint8_t ether_dhost[6];
  uint8_t ether_shost[6];
  uint8_t ether_type[2];
  uint8_t vlan_tag[2];
} __attribute__((__packed__));

PacketCapture::PacketCapture(const char *interface)
    : handle(nullptr), iface(interface) {}

PacketCapture::~PacketCapture() {
  if (handle != nullptr) {
    pcap_close(handle);
  }
}
void PacketCapture::prepare(fd_set *read_fds, fd_set *write_fds,
                            fd_set *err_fds, int &max_fd,
                            unsigned long long &min_timeout) {
  if (handle == nullptr) {
    if (pcap_lookupnet(iface.c_str(), &net, &mask, error_buffer) == -1) {
      net = 0;
      mask = 0;
    }
    handle = pcap_open_live(iface.c_str(), 100, false, 1000, error_buffer);
    if (handle == nullptr) {
      if (min_timeout == 0 || min_timeout < RETRY_THRESHOLD) {
        min_timeout = RETRY_THRESHOLD;
      }
      return;
    }
    if (pcap_setnonblock(handle, 1, error_buffer) == -1) {
      pcap_close(handle);
      handle == nullptr;
      return;
    }
    switch (pcap_datalink(handle)) {
    case DLT_EN10MB:
      ip_offset = 14;
      break;
#ifdef DLT_LINUX_SLL
    case DLT_LINUX_SLL:
      ip_offset = 16;
      break;
#endif
#ifdef DLT_RAW
    case DLT_RAW:
      ip_offset = 0;
      break;
#endif
    case DLT_IEEE802:
      ip_offset = 22;
      break;
    default:
      ip_offset = 0;
    }
  }

  int pcap_fd = pcap_get_selectable_fd(handle);
  FD_SET(pcap_fd, read_fds);
  FD_SET(pcap_fd, err_fds);
  if (pcap_fd > max_fd) {
    max_fd = pcap_fd;
  }
}

void PacketCapture::updateAddress(uint32_t ip, std::string &output) {
  if (net != 0 && (ip & mask) == net) {
    struct in_addr addr;
    addr.s_addr = ip;
    output = inet_ntoa(addr);
  }
}

void PacketCapture::service(fd_set *read_fds, fd_set *write_fds,
                            fd_set *err_fds) {
  if (handle == nullptr)
    return;
  while (true) {
    struct pcap_pkthdr *header;
    const u_char *packet;
    switch (pcap_next_ex(handle, &header, &packet)) {

    case -1:
      pcap_close(handle);
      handle = nullptr;
      return;

    case 0:
      return;
    }

    auto vlanhdr = (struct vlan_header *)packet;
    int extra =
        (vlanhdr->ether_type[0] == 0x81 && vlanhdr->ether_type[1] == 0x00) ? 4
                                                                           : 0;
    struct ip *ip = (struct ip *)(packet + ip_offset + extra);
    std::string source_host("unknown");
    std::string dest_host("unknown");
    if (ip->ip_v == 4) {
      updateAddress(*(uint32_t *)(&ip->ip_src), source_host);
      updateAddress(*(uint32_t *)(&ip->ip_dst), dest_host);
    }
    auto bytes = header->caplen - ip_offset - extra;
    struct host_stats &source_stats = entries[source_host];
    source_stats.write_packets++;
    source_stats.write_bytes += bytes;
    struct host_stats &dest_stats = entries[dest_host];
    dest_stats.read_packets++;
    dest_stats.read_bytes += bytes;
  }
}
const std::string &PacketCapture::interface() const { return iface; }
std::map<std::string, struct host_stats>::const_iterator
PacketCapture::begin() const {
  return entries.begin();
}
std::map<std::string, struct host_stats>::const_iterator
PacketCapture::end() const {
  return entries.end();
}
bool PacketCapture::isOnline() const { return handle != nullptr; }
void PacketCapture::clear() { entries.clear(); }
