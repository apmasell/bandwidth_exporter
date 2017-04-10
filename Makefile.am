NULL = 
ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS = bandwidth_exporter
systemddir=$(libdir)/systemd/system
systemd_DATA = bandwidth_exporter.service
man1_MANS = bandwidth_exporter.1

bandwidth_exporter_CPPFLAGS = \
	-std=c++11 \
	$(PCAP_CFLAGS) \
	$(MHD_CFLAGS) \
	-g -O2 \
	$(NULL)
bandwidth_exporter_LDADD = \
	$(PCAP_LIBS) \
	$(MHD_LIBS) \
	$(NULL)
bandwidth_exporter_SOURCES = \
	http.cpp \
	main.cpp \
	network.cpp \
	$(NULL)
