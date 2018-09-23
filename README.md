[![logo](https://raw.githubusercontent.com/dperson/openvpn-client/master/logo.png)](https://openvpn.net/)

# OpenVPN

This is an OpenVPN client docker container. It makes routing containers'
traffic through OpenVPN easy.

# What is OpenVPN?

OpenVPN is an open-source software application that implements virtual private
network (VPN) techniques for creating secure point-to-point or site-to-site
connections in routed or bridged configurations and remote access facilities.
It uses a custom security protocol that utilizes SSL/TLS for key exchange. It is
capable of traversing network address translators (NATs) and firewalls.

# How to use this image

This OpenVPN container was designed to be started first to provide a connection
to other containers (using `--net=container:vpn`, see below *Starting an OpenVPN
client instance*).

**NOTE**: More than the basic privileges are needed for OpenVPN. With docker 1.2
or newer you can use the `--cap-add=NET_ADMIN` and `--device /dev/net/tun`
options. Earlier versions, or with fig, and you'll have to run it in privileged
mode.

**NOTE 2**: If you have connectivity issues, please see the DNS instructions
below.

**NOTE 3**: If you need access to other non HTTP proxy-able ports, please see
the Routing instructions below.

**NOTE 4**: If you have a VPN service that allows making local services
available, you'll need to reuse the VPN container's network stack with the
`--net=container:vpn` (replacing 'vpn' with what you named your instance of this
container) when you launch the service in it's container.

**NOTE 5**: If you need a template for using this container with
`docker-compose`, see the example
[file](https://github.com/dperson/openvpn-client/raw/master/docker-compose.yml).

## Starting an OpenVPN client instance

    sudo cp /path/to/vpn.crt /some/path/vpn-ca.crt
    sudo docker run -it --cap-add=NET_ADMIN --device /dev/net/tun --name vpn \
                -v /some/path:/vpn -d dperson/openvpn-client \
                -v 'vpn.server.name;username;password'
    sudo docker restart vpn

Once it's up other containers can be started using it's network connection:

    sudo docker run -it --net=container:vpn -d some/docker-container

## Local Network access to services connecting to the internet through the VPN.

However to access them from your normal network (off the 'local' docker bridge),
you'll also need to run a web proxy, like so:

    sudo docker run -it --name web -p 80:80 -p 443:443 \
                --link vpn:<service_name> -d dperson/nginx \
                -w "http://<service_name>:<PORT>/<URI>;/<PATH>"

Which will start a Nginx web server on local ports 80 and 443, and proxy any
requests under `/<PATH>` to the to `http://<service_name>:<PORT>/<URI>`. To use
a concrete example:

    sudo docker run -it --name bit --net=container:vpn -d dperson/transmission
    sudo docker run -it --name web -p 80:80 -p 443:443 --link vpn:bit \
                -d dperson/nginx -w "http://bit:9091/transmission;/transmission"

For multiple services (non-existant 'foo' used as an example):

    sudo docker run -it --name bit --net=container:vpn -d dperson/transmission
    sudo docker run -it --name foo --net=container:vpn -d dperson/foo
    sudo docker run -it --name web -p 80:80 -p 443:443 --link vpn:bit \
                --link vpn:foo -d dperson/nginx \
                -w "http://bit:9091/transmission;/transmission" \
                -w "http://foo:8000/foo;/foo"

## Routing for local access to non HTTP proxy-able ports

The argument to the `-r` (route) command line argument must be your local
network that you would connect to the server running the docker containers on.
Running the following on your docker host should give you the correct network:
`ip route | awk '!/ (docker0|br-)/ && /src/ {print $1}'`

    sudo cp /path/to/vpn.crt /some/path/vpn-ca.crt
    sudo docker run -it --cap-add=NET_ADMIN --device /dev/net/tun --name vpn \
                -v /some/path:/vpn -d dperson/openvpn-client \
                -r 192.168.1.0/24 -v 'vpn.server.name;username;password'

**NOTE**: if you don't use the `-v` to configure your VPN, then you'll have to
make sure that `redirect-gateway def1` is set, otherwise routing may not work.

**NOTE 2**: if you have a port you want to make available, you have to add the
docker `-p` option to the VPN container. The network stack will be reused by
the second container (that's what `--net=container:vpn` does).

## Configuration

    sudo docker run -it --rm dperson/openvpn-client -h

    Usage: openvpn.sh [-opt] [command]
    Options (fields in '[]' are optional, '<>' are required):
        -h          This help
        -c '<passwd>' Configure an authentication password to open the cert
                    required arg: '<passwd>'
                    <passwd> password to access the certificate file
        -d          Use the VPN provider's DNS resolvers
        -f '[port]' Firewall rules so that only the VPN and DNS are allowed to
                    send internet traffic (IE if VPN is down it's offline)
                    optional arg: [port] to use, instead of default
        -m '<mss>'  Maximum Segment Size <mss>
                    required arg: '<mss>'
        -p '<port>[;protocol]' Forward port <port>
                    required arg: '<port>'
                    optional arg: [protocol] to use instead of default (tcp)
        -R '<network>' CIDR IPv6 network (IE fe00:d34d:b33f::/64)
                    required arg: '<network>'
                    <network> add a route to (allows replies once the VPN is up)
        -r '<network>' CIDR network (IE 192.168.1.0/24)
                    required arg: '<network>'
                    <network> add a route to (allows replies once the VPN is up)
        -v '<server;user;password[;port]>' Configure OpenVPN
                    required arg: '<server>;<user>;<password>'
                    <server> to connect to (multiple servers are separated by :)
                    <user> to authenticate as
                    <password> to authenticate with
                    optional arg: [port] to use, instead of default

    The 'command' (if provided and valid) will be run instead of openvpn

ENVIRONMENT VARIABLES

 * `CERT_AUTH` - As above, provide authentication to access certificate
 * `DNS` - As above, Use the VPN provider's DNS resolvers
 * `FIREWALL` - As above, setup firewall to disallow net access w/o the VPN
 * `MSS` - As above, set Maximum Segment Size
 * `ROUTE6` - As above, add a route to allow replies to your internal network
 * `ROUTE` - As above, add a route to allow replies to your private network
 * `TZ` - Set a timezone, IE `EST5EDT`
 * `VPN` - As above, setup a VPN connection
 * `VPNPORT` - As above, setup port forwarding
 * `GROUPID` - Set the GID for the vpn

## Examples

Any of the commands can be run at creation with `docker run` or later with
`docker exec -it openvpn openvpn.sh` (as of version 1.3 of docker).

### Setting the Timezone

    sudo cp /path/to/vpn.crt /some/path/vpn-ca.crt
    sudo docker run -it --cap-add=NET_ADMIN --device /dev/net/tun --name vpn \
                -v /some/path:/vpn -e TZ=EST5EDT -d dperson/openvpn \
                -v 'vpn.server.name;username;password'

### VPN configuration

In order to work you must provide VPN configuration and the certificate. You can
use external storage for `/vpn`:

    sudo cp /path/to/vpn.crt /some/path/vpn-ca.crt
    sudo docker run -it --cap-add=NET_ADMIN --device /dev/net/tun --name vpn \
                -v /some/path:/vpn -d dperson/openvpn-client \
                -v 'vpn.server.name;username;password'

Or you can store it in the container:

    cat /path/to/vpn.crt | sudo docker run -it --cap-add=NET_ADMIN \
                --device /dev/net/tun --name vpn -d dperson/openvpn-client \
                -v 'vpn.server.name;username;password' tee /vpn/vpn-ca.crt \
                >/dev/null
    sudo docker restart vpn

### Firewall

It's just a simple command line argument (`-f ""`) to turn on the firewall, and
block all outbound traffic if the VPN is down.

    sudo cp /path/to/vpn.crt /some/path/vpn-ca.crt
    sudo docker run -it --cap-add=NET_ADMIN --device /dev/net/tun --name vpn \
                -v /some/path:/vpn -d dperson/openvpn-client -f "" \
                -v 'vpn.server.name;username;password'

### DNS Issues (May Look Like You Can't Connect To Anything)

Often local DNS and/or your ISP won't be accessable from the new IP address you
get from your VPN. You'll need to add the `--dns` command line option to the
`docker run` statement. Here's an example of doing so, with a Google DNS server:

    sudo cp /path/to/vpn.crt /some/path/vpn-ca.crt
    sudo docker run -it --cap-add=NET_ADMIN --device /dev/net/tun --name vpn \
                --dns 8.8.4.4 -v /some/path:/vpn -d dperson/openvpn-client \
                -v 'vpn.server.name;username;password'

# User Feedback

## Issues

If you have any problems with or questions about this image, please contact me
through a [GitHub issue](https://github.com/dperson/openvpn-client/issues).