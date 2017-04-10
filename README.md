# bandwidth_exporter

This runs on a router and monitors an interface and collects stats on how much data the hosts have transmitted. It provides the collected stats via an interface that [Prometheus](https://prometheus.io/) can scrape.

## Installation
If you have Ubuntu, you can install it automagically:

    apt-add-reporistory ppa:apmasell/ppa
    apt-get update
    apt-get install bandwidth-exporter

And then the interface will be scrapable via [:9313](http://localhost:9313).

## Compilation
To compile it, you will need [pcap](http://www.tcpdump.org/) and [libmicrohttpd](https://www.gnu.org/software/libmicrohttpd/). You can install these on Debian/Ubuntu by invoking:

    apt-get install libpcap-dev libmicrohttpd-dev autotools-dev

You can build it from source using the typical:

    autoreconf -i
    ./configure
    make
    make install
