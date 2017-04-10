#include "bandwidth_exporter.hpp"
#include <cstring>
#include <memory>
#include <sstream>

#define VARDEF(varname, help)                                                  \
  ("# HELP bandwidth_" varname " " help "\n# TYPE bandwidth_" varname          \
   " counter\n")

static void write_var(std::stringstream &stream, const char *variable,
                      const std::string &host, unsigned long value) {
  stream << "bandwidth_" << variable << "{host=" << host << "} " << value
         << "\n";
}

static int handler(void *cls, struct MHD_Connection *connection,
                   const char *url, const char *method, const char *version,
                   const char *upload_data, size_t *upload_data_size,
                   void **ptr) {

  if (0 != strcmp(method, MHD_HTTP_METHOD_GET))
    return MHD_NO;
  std::stringstream response_string;
  response_string << VARDEF("read_packets", "Packets received from this host.")
                  << VARDEF("write_packets", "Packets sent to this host.")
                  << VARDEF("read_bytes",
                            "Total bytes received from this host.")
                  << VARDEF("write_bytes", "Total bytes sent to this host.");

  for (auto it = entries.begin(); it != entries.end(); it++) {
    write_var(response_string, "read_packets", it->first,
              it->second.read_packets);
    write_var(response_string, "write_packets", it->first,
              it->second.write_packets);
    write_var(response_string, "read_bytes", it->first, it->second.read_bytes);
    write_var(response_string, "write_bytes", it->first,
              it->second.write_bytes);
  }

  std::shared_ptr<MHD_Response> response(
      MHD_create_response_from_buffer(strlen(response_string.str().c_str()),
                                      (void *)response_string.str().c_str(),
                                      MHD_RESPMEM_MUST_COPY),
      MHD_destroy_response);
  return MHD_queue_response(connection, MHD_HTTP_OK, response.get());
}

HttpServer::HttpServer(unsigned short port) throw(std::runtime_error) {
  http_server = MHD_start_daemon(MHD_USE_DUAL_STACK, port, NULL, NULL, &handler,
                                 nullptr, MHD_OPTION_END);
  if (http_server == nullptr) {
    throw std::runtime_error("Could not configure HTTP server.");
  }
}
HttpServer::~HttpServer() { MHD_stop_daemon(http_server); }

void HttpServer::prepare(
    fd_set *read_fds, fd_set *write_fds, fd_set *err_fds, int &max_fd,
    unsigned long long &min_timeout) throw(std::runtime_error) {
  MHD_socket http_max_fd = 0;
  if (MHD_YES !=
      MHD_get_fdset(http_server, read_fds, write_fds, err_fds, &http_max_fd))
    throw std::runtime_error("Failed to get HTTP file descriptors.");

  if (max_fd < http_max_fd) {
    max_fd = http_max_fd;
  }

  MHD_UNSIGNED_LONG_LONG http_timeout;
  if (MHD_get_timeout(http_server, &http_timeout) == MHD_YES) {
    if (min_timeout == 0 || min_timeout > http_timeout) {
      min_timeout = http_timeout;
    }
  }
}

void HttpServer::service(fd_set *read_fds, fd_set *write_fds, fd_set *err_fds) {
  MHD_run_from_select(http_server, read_fds, write_fds, err_fds);
}
