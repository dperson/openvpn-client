FROM ubuntu:trusty
MAINTAINER David Personette <dperson@dperson.com>

# Install openvpn
RUN export DEBIAN_FRONTEND='noninteractive' && \
    apt-get update -qq && \
    apt-get install -qqy --no-install-recommends openvpn && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/*
COPY openvpn.sh /usr/bin/

VOLUME ["/vpn"]

ENTRYPOINT ["openvpn.sh"]
