##################
# OpenVPN Client #
#   Dockerfile   #
##################

FROM alpine
MAINTAINER David Personette <dperson@dperson.com>

# Install openvpn
RUN \
    echo http://dl-4.alpinelinux.org/alpine/edge/testing >> /etc/apk/repositories && \
    apk update && \
    apk add bash shadow iptables openvpn && \
    rm -rf /var/cache/apk/* && \
    addgroup -S vpn

COPY openvpn.sh /usr/bin/

VOLUME ["/vpn"]
WORKDIR /vpn

ENTRYPOINT ["openvpn.sh"]
