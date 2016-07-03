#!/usr/bin/env bash
#===============================================================================
#          FILE: openvpn.sh
#
#         USAGE: ./openvpn.sh
#
#   DESCRIPTION: Entrypoint for openvpn docker container
#
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: David Personette (dperson@gmail.com),
#  ORGANIZATION:
#       CREATED: 09/28/2014 12:11
#      REVISION: 1.0
#===============================================================================

set -o nounset                              # Treat unset variables as an error

### dns: setup openvpn client DNS
# Arguments:
#   none)
# Return: conf file that uses VPN provider's DNS resolvers
dns() { local conf="/vpn/vpn.conf"

    sed -i '/resolv-*conf/d; /script-security/d' $conf
    echo "# This updates the resolvconf with dns settings" >>$conf
    echo "script-security 2" >>$conf
    echo "up /etc/openvpn/update-resolv-conf" >>$conf
    echo "down /etc/openvpn/update-resolv-conf" >>$conf
}

### firewall: firewall all output not DNS/VPN that's not over the VPN
# Arguments:
#   none)
# Return: configured firewall
firewall() {
    local docker_network=$(ip -o addr show dev eth0 |
                awk '$3 == "inet" {print $4}')

    iptables -F OUTPUT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -o tap0 -j ACCEPT
    iptables -A OUTPUT -o tun0 -j ACCEPT
    iptables -A OUTPUT -d ${docker_network} -j ACCEPT
    iptables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null &&
    iptables -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT || {
        iptables -A OUTPUT -p tcp -m tcp --dport 1194 -j ACCEPT
        iptables -A OUTPUT -p udp -m udp --dport 1194 -j ACCEPT; }
    iptables -A OUTPUT -j DROP
}

### return_route: add a route back to your network, so that return traffic works
# Arguments:
#   network) a CIDR specified network range
# Return: configured return route
return_route() { local gw network="$1"
    gw=$(ip route | awk '/default/ {print $3}')
    ip route add to $network via $gw dev eth0
}

### timezone: Set the timezone for the container
# Arguments:
#   timezone) for example EST5EDT
# Return: the correct zoneinfo file will be symlinked into place
timezone() { local timezone="${1:-EST5EDT}"
    [[ -e /usr/share/zoneinfo/$timezone ]] || {
        echo "ERROR: invalid timezone specified: $timezone" >&2
        return
    }

    if [[ -w /etc/timezone && $(cat /etc/timezone) != $timezone ]]; then
        echo "$timezone" >/etc/timezone
        ln -sf /usr/share/zoneinfo/$timezone /etc/localtime
        dpkg-reconfigure -f noninteractive tzdata >/dev/null 2>&1
    fi
}

### vpn: setup openvpn client
# Arguments:
#   server) VPN GW server
#   user) user name on VPN
#   pass) password on VPN
# Return: configured .ovpn file
vpn() { local server="$1" user="$2" pass="$3" \
            conf="/vpn/vpn.conf" auth="/vpn/vpn.auth"

    cat >$conf <<-EOF
		client
		dev tun
		proto udp
		remote $server 1194
		resolv-retry infinite
		nobind
		persist-key
		persist-tun
		ca /vpn/vpn-ca.crt
		tls-client
		remote-cert-tls server
		auth-user-pass
		comp-lzo
		verb 1
		reneg-sec 0
		redirect-gateway def1
		auth-user-pass $auth
		EOF

    echo "$user" >$auth
    echo "$pass" >>$auth
    chmod 0600 $auth
}

### vpnportforward: setup vpn port forwarding
# Arguments:
#   port) forwarded port
# Return: configured NAT rule
vpnportforward() {
    local port="$1"
    iptables -t nat -A OUTPUT -p tcp --dport $port -j DNAT --to-destination 127.0.0.11:$port
    echo "Setup forwarded port: $port"
}

### usage: Help
# Arguments:
#   none)
# Return: Help text
usage() { local RC=${1:-0}

    echo "Usage: ${0##*/} [-opt] [command]
Options (fields in '[]' are optional, '<>' are required):
    -h          This help
    -d          Use the VPN provider's DNS resolvers
    -f          Firewall rules so that only the VPN and DNS are allowed to
                send internet traffic (IE if VPN is down it's offline)
    -p \"<port>\" Forward port <port>
                  required arg: \"<port>\"
    -r \"<network>\" CIDR network (IE 192.168.1.0/24)
                required arg: \"<network>\"
                <network> add a route to (allows replies once the VPN is up)
    -t \"\"       Configure timezone
                possible arg: \"[timezone]\" - zoneinfo timezone for container
    -v '<server;user;password>' Configure OpenVPN
                required arg: \"<server>;<user>;<password>\"
                <server> to connect to
                <user> to authenticate as
                <password> to authenticate with

The 'command' (if provided and valid) will be run instead of openvpn
" >&2
    exit $RC
}

while getopts ":hdfp:r:t:v:" opt; do
    case "$opt" in
        h) usage ;;
        d) DNS=true ;;
        f) firewall; touch /vpn/.firewall ;;
        p) vpnportforward "$OPTARG" ;;
        r) return_route "$OPTARG" ;;
        t) timezone "$OPTARG" ;;
        v) eval vpn $(sed 's/^\|$/"/g; s/;/" "/g' <<< $OPTARG) ;;
        "?") echo "Unknown option: -$OPTARG"; usage 1 ;;
        ":") echo "No argument value for option: -$OPTARG"; usage 2 ;;
    esac
done
shift $(( OPTIND - 1 ))

[[ "${FIREWALL:-""}" || -e /vpn/.firewall ]] && firewall
[[ "${ROUTE:-""}" ]] && return_route "$ROUTE"
[[ "${TZ:-""}" ]] && timezone "$TZ"
[[ "${VPN:-""}" ]] && eval vpn $(sed 's/^\|$/"/g; s/;/" "/g' <<< $VPN)
[[ "${DNS:-""}" ]] && dns
[[ "${VPNPORT:-""}" ]] && vpnportforward "$VPNPORT"

if [[ $# -ge 1 && -x $(which $1 2>&-) ]]; then
    exec "$@"
elif [[ $# -ge 1 ]]; then
    echo "ERROR: command not found: $1"
    exit 13
elif ps -ef | egrep -v 'grep|openvpn.sh' | grep -q openvpn; then
    echo "Service already running, please restart container to apply changes"
else
    [[ -e /vpn/vpn.conf ]] || { echo "ERROR: VPN not configured!"; sleep 120; }
    [[ -e /vpn/vpn-ca.crt ]] || { echo "ERROR: VPN cert missing!"; sleep 120; }
    exec sg vpn -c "openvpn --config /vpn/vpn.conf"
fi