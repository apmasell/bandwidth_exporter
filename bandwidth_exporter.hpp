#pragma once
#include <map>
#include <memory>
#include <microhttpd.h>
#include <pcap.h>
#include <stdexcept>
#include <string>
#include <sys/select.h>
#include <vector>

struct host_stats {
  unsigned long read_packets;
  unsigned long write_packets;
  unsigned long read_bytes;
  unsigned long write_bytes;
};

class HttpServer {
public:
  HttpServer(unsigned short port) throw(std::runtime_error);
  ~HttpServer();
  void prepare(fd_set *read_fds, fd_set *write_fds, fd_set *err_fds,
               int &max_fd,
               unsigned long long &min_timeout) throw(std::runtime_error);

  void service(fd_set *read_fds, fd_set *write_fds, fd_set *err_fds);

private:
  struct MHD_Daemon *http_server;
};

class PacketCapture {
public:
  PacketCapture(const char *interface);
  ~PacketCapture();
  void prepare(fd_set *read_fds, fd_set *write_fds, fd_set *err_fds,
               int &max_fd, unsigned long long &min_timeout);

  void service(fd_set *read_fds, fd_set *write_fds, fd_set *err_fds);
  const std::string &interface() const;
  std::map<std::string, struct host_stats>::const_iterator begin() const;
  std::map<std::string, struct host_stats>::const_iterator end() const;
  bool isOnline() const;
  void clear();

private:
  void updateAddress(uint32_t ip, std::string &output);
  pcap_t *handle;
  char error_buffer[PCAP_ERRBUF_SIZE];
  size_t ip_offset;
  uint32_t net;
  uint32_t mask;
  std::string iface;
  std::map<std::string, struct host_stats> entries;
};

extern std::vector<std::shared_ptr<PacketCapture>> captures;
