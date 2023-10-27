FROM alpine
MAINTAINER Richard Sarkis <rich@sark.is>

# Install openvpn
RUN apk --no-cache --no-progress upgrade && \
    apk --no-cache --no-progress add bash \
                                     curl \
                                     grep \
                                     ip6tables \
                                     iptables \
                                     openvpn \
                                     shadow-login \
                                     tini \
                                     tzdata && \
    addgroup -S vpn && \
    rm -rf /tmp/*

COPY openvpn.sh /usr/bin/

HEALTHCHECK --interval=60s --timeout=15s --start-period=120s \
             CMD curl -LSs 'https://api.ipify.org'

VOLUME ["/vpn"]

ENTRYPOINT ["/sbin/tini", "--", "/usr/bin/openvpn.sh"]
