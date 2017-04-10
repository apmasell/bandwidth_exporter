#include "bandwidth_exporter.hpp"
#include <climits>
#include <csignal>
#include <getopt.h>
#include <iostream>
#include <microhttpd.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

volatile bool running = true;

std::map<std::string, struct host_stats> entries;

void begin_death(int signum) { running = false; }

void clear_entries(int signum) { entries.clear(); }

int main(int argc, char *const *argv) {
  const char *interface = nullptr;
  unsigned short port = 9131;

  int opt;
  while ((opt = getopt(argc, argv, "I:p:")) != -1) {
    switch (opt) {
    case 'I':
      interface = optarg;
      break;
    case 'p':
      port = atoi(optarg);
      break;
    default:
      std::cerr << "Usage: " << argv[0] << " -I interface [-p port]"
                << std::endl;
      return 1;
    }
  }

  if (optind < argc) {
    std::cerr << "Unexpected argument after options." << std::endl;
    return 1;
  }
  if (interface == nullptr) {
    std::cerr << "Network interface must be specified." << std::endl;
    return 1;
  }

  HttpServer http(port);
  PacketCapture capture(interface);
  signal(SIGHUP, clear_entries);
  signal(SIGINT, begin_death);
  signal(SIGTERM, begin_death);

  while (running) {
    struct timeval timeout;
    int max_fd = 0;
    unsigned long long min_timeout = 0;
    fd_set read_fds;
    fd_set write_fds;
    fd_set err_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    FD_ZERO(&err_fds);

    http.prepare(&read_fds, &write_fds, &err_fds, max_fd, min_timeout);
    capture.prepare(&read_fds, &write_fds, &err_fds, max_fd);

    timeout.tv_sec = min_timeout / 1000LL;
    timeout.tv_usec = min_timeout % 1000LL;
    errno = 0;
    if (-1 == select(max_fd + 1, &read_fds, &write_fds, &err_fds,
                     min_timeout == 0 ? nullptr : &timeout) &&
        errno != EINTR) {
      return 1;
    } else if (errno == 0) {
      http.service(&read_fds, &write_fds, &err_fds);
      capture.service(&read_fds, &write_fds, &err_fds);
    }
  }
  return 0;
}
