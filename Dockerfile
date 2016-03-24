FROM debian:jessie
MAINTAINER David Personette <dperson@dperson.com>

# Install openvpn
RUN export DEBIAN_FRONTEND='noninteractive' && \
    apt-get update -qq && \
    apt-get install -qqy --no-install-recommends iptables openvpn easy-rsa wget \
                $(apt-get -s dist-upgrade|awk '/^Inst.*ecurity/ {print $2}') &&\
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* && \
    addgroup --system vpn
COPY openvpn.sh /usr/bin/

ENV KEY_NAME="server"
ENV KEY_COUNTRY="US"
ENV KEY_PROVINCE="TX"
ENV KEY_CITY="Dallas"
ENV KEY_ORG="My Company Name"
ENV KEY_EMAIL="sammy@example.com"
ENV KEY_OU="MYOrganizationalUnit"

VOLUME ["/vpn"]

ENTRYPOINT ["openvpn.sh"]
