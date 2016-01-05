[![logo](https://raw.githubusercontent.com/dperson/openvpn-client/master/logo.png)](https://openvpn.net/)

# OpenVPN

OpenVPN client docker container

# What is OpenVPN?

OpenVPN is an open-source software application that implements virtual private
network (VPN) techniques for creating secure point-to-point or site-to-site
connections in routed or bridged configurations and remote access facilities.
It uses a custom security protocol that utilizes SSL/TLS for key exchange. It is
capable of traversing network address translators (NATs) and firewalls.

# How to use this image

This OpenVPN container was designed to be started first to provide a connection
to other containers (using `--net=container:vpn`, see below).

**NOTE**: More than the basic privileges are needed for OpenVPN. With docker 1.2
or newer you can use the `--cap-add=NET_ADMIN` and `--device /dev/net/tun`
options. Earlier versions, or with fig, and you'll have to run it in privileged
mode.

**NOTE 2**: If you have connectivity issues, please see the DNS instructions
below.

## Hosting an OpenVPN client instance

    sudo docker run --cap-add=NET_ADMIN --device /dev/net/tun --name vpn \
                -v /some/path:/vpn -d dperson/openvpn-client \
                -v "vpn.server.name;username;password"
    sudo cp /path/to/vpn.crt /some/path/vpn-ca.crt
    sudo docker restart vpn

Once it's up other containers can be started using it's network connection:

    sudo docker run --net=container:vpn -d some/docker-container

## Local Network access to services connecting to the internet through the VPN.

However to access them from your normal network (off the 'local' docker bridge),
you'll also need to run a web proxy, like so:

    sudo docker run --name web -p 80:80 -p 443:443 --link vpn:<service_name> \
                -d dperson/nginx -w "http://<service_name>:<PORT>/<URI>;/<PATH>"

Which will start a Nginx web server on local ports 80 and 443, and proxy any
requests under `/<PATH>` to the to `http://<service_name>:<PORT>/<URI>`. To use
a concrete example:

    sudo docker run --name bit --net=container:vpn -d dperson/transmission
    sudo docker run --name web -p 80:80 -p 443:443 --link vpn:bit \
                -d dperson/nginx -w "http://bit:9091/transmission;/transmission"

## Configuration

    sudo docker run -it --rm dperson/openvpn-client -h

    Usage: openvpn.sh [-opt] [command]
    Options (fields in '[]' are optional, '<>' are required):
        -h          This help
        -f          Firewall rules so that only the VPN and DNS are allowed to
                    send internet traffic (IE if VPN is down it's offline)
        -t ""       Configure timezone
                    possible arg: "[timezone]" - zoneinfo timezone for container
        -v "<server;user;password>" Configure OpenVPN
                    required arg: "<server>;<user>;<password>"
                    <server> to connect to
                    <user> to authenticate as
                    <password> to authenticate with

    The 'command' (if provided and valid) will be run instead of openvpn

ENVIRONMENT VARIABLES (only available with `docker run`)

 * `TZ` - As above, set a zoneinfo timezone, IE `EST5EDT`
 * `VPN` - As above, setup a VPN connection

## Examples

Any of the commands can be run at creation with `docker run` or later with
`docker exec openvpn.sh` (as of version 1.3 of docker).

### Setting the Timezone

    sudo cp /path/to/vpn.crt /some/path/vpn-ca.crt
    sudo docker run --cap-add=NET_ADMIN --device /dev/net/tun --name vpn \
                -v /some/path:/vpn -d dperson/openvpn-client -t EST5EDT \
                -v "vpn.server.name;username;password"

OR using `environment variables`

    sudo cp /path/to/vpn.crt /some/path/vpn-ca.crt
    sudo docker run --cap-add=NET_ADMIN --device /dev/net/tun --name vpn \
                -v /some/path:/vpn -e TZ=EST5EDT -d dperson/openvpn \
                -v "vpn.server.name;username;password"

Will get you the same settings as:

    sudo cp /path/to/vpn.crt /some/path/vpn-ca.crt
    sudo docker run --cap-add=NET_ADMIN --device /dev/net/tun --name vpn \
                -v /some/path:/vpn -d dperson/openvpn-client \
                -v "vpn.server.name;username;password"
    sudo docker exec vpn openvpn.sh -t EST5EDT ls -AlF /etc/localtime
    sudo docker restart vpn

### VPN configuration

In order to work you must provide VPN configuration and the certificate. You can
use external storage for `/vpn`:

    sudo docker run --cap-add=NET_ADMIN --device /dev/net/tun --name vpn \
                -v /some/path:/vpn -d dperson/openvpn-client \
                -v "vpn.server.name;username;password"
    sudo cp /path/to/vpn.crt /some/path/vpn-ca.crt
    sudo docker restart vpn

Or you can store it in the container:

    cat /path/to/vpn.crt | sudo docker run -i --cap-add=NET_ADMIN \
                --device /dev/net/tun --name vpn -d dperson/openvpn-client \
                -v "vpn.server.name;username;password" tee /vpn/vpn-ca.crt \
                >/dev/null
    sudo docker restart vpn

### Firewall

It's just a simple command line argument (`-f`) to turn on the firewall, and
block all outbound traffic if the VPN is down.

    sudo docker run --cap-add=NET_ADMIN --device /dev/net/tun --name vpn \
                -v /some/path:/vpn -d dperson/openvpn-client -f \
                -v "vpn.server.name;username;password"
    sudo cp /path/to/vpn.crt /some/path/vpn-ca.crt
    sudo docker restart vpn

### DNS Issues (May Look Like You Can't Connect To Anything)

Often local DNS and/or your ISP won't be accessable from the new IP address you
get from your VPN. You'll need to add the `--dns` command line option to the
`docker run` statement. Here's an example of doing so, with a Google DNS server:

    sudo cp /path/to/vpn.crt /some/path/vpn-ca.crt
    sudo docker run --cap-add=NET_ADMIN --device /dev/net/tun --name vpn \
                --dns 8.8.4.4 -v /some/path:/vpn -d dperson/openvpn-client \
                -v "vpn.server.name;username;password"

# User Feedback

## Issues

If you have any problems with or questions about this image, please contact me
through a [GitHub issue](https://github.com/dperson/openvpn-client/issues).
