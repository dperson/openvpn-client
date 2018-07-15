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

### cert_auth: setup auth passwd for accessing certificate
# Arguments:
#   passwd) Password to access the cert
# Return: conf file that supports certificate authentication
cert_auth() { local passwd="$1"
    grep -q "^${passwd}\$" "$auth" || {
        echo "$passwd" >"$auth"
    }
    chmod 0600 "$auth"
    grep -q "^askpass ${auth}\$" "$conf" || {
        sed -i '/askpass/d' "$conf"
        echo "askpass $auth" >>"$conf"
    }
}

### dns: setup openvpn client DNS
# Arguments:
#   none)
# Return: conf file that uses VPN provider's DNS resolvers
dns() {
    sed -i '/resolv-*conf/d; /script-security/d' "$conf"
    {
      echo "# This updates the resolvconf with dns settings"
      echo "script-security 2"
      echo "up /etc/openvpn/up.sh"
      echo "down /etc/openvpn/down.sh"
    } >>"$conf"
}

### firewall: firewall all output not DNS/VPN that's not over the VPN connection
# Arguments:
#   none)
# Return: configured firewall
firewall() { local port docker_network network docker6_network
    port="${1:-1194}"
    docker_network="$(ip -o addr show dev eth0 | awk '$3 == "inet" {print $4}')"
    docker6_network="$(ip -o addr show dev eth0 | awk '$3 == "inet6" {print $4; exit}')"

    [[ -z "${1:-""}" && -r $conf ]] &&
        port="$(awk '/^remote / && NF ~ /^[0-9]*$/ {print $NF}' "$conf" |
                    grep ^ || echo 1194)"

    ip6tables -F OUTPUT 2>/dev/null
    ip6tables -P OUTPUT DROP 2>/dev/null
    ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT \
                2>/dev/null
    ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null
    ip6tables -A OUTPUT -o tap0 -j ACCEPT 2>/dev/null
    ip6tables -A OUTPUT -o tun0 -j ACCEPT 2>/dev/null
    ip6tables -A OUTPUT -d "${docker6_network}" -j ACCEPT 2>/dev/null
    ip6tables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT 2>/dev/null
    # shellcheck disable=SC2015
    ip6tables -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null &&
    ip6tables -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null || {
        ip6tables -A OUTPUT -p tcp -m tcp --dport "$port" -j ACCEPT 2>/dev/null
        ip6tables -A OUTPUT -p udp -m udp --dport "$port" -j ACCEPT 2>/dev/null
    }
    iptables -F OUTPUT
    iptables -P OUTPUT DROP
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -o tap0 -j ACCEPT
    iptables -A OUTPUT -o tun0 -j ACCEPT
    iptables -A OUTPUT -d "${docker_network}" -j ACCEPT
    iptables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
    # shellcheck disable=SC2015
    iptables -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null &&
    iptables -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT || {
        iptables -A OUTPUT -p tcp -m tcp --dport "$port" -j ACCEPT
        iptables -A OUTPUT -p udp -m udp --dport "$port" -j ACCEPT
    }
    # shellcheck disable=SC2013
    [[ -s $route6 ]] && for net in $(cat "$route6"); do return_route6 "$net"; done
    # shellcheck disable=SC2013
    [[ -s $route ]] && for net in $(cat "$route"); do return_route "$net"; done
}

### return_route: add a route back to your network, so that return traffic works
# Arguments:
#   network) a CIDR specified network range
# Return: configured return route
return_route6() { local network gw
    network="$1"
    gw="$(ip -6 route | awk '/default/{print $3}')"
    ip -6 route | grep -q "$network" ||
        ip -6 route add to "$network" via "$gw" dev eth0
    ip6tables -A OUTPUT --destination "$network" -j ACCEPT 2>/dev/null
    [[ -e $route6 ]] &&grep -q "^$network\$" "$route6" ||echo "$network" >>"$route6"
}

### return_route: add a route back to your network, so that return traffic works
# Arguments:
#   network) a CIDR specified network range
# Return: configured return route
return_route() { local network gw
    network="$1"
    gw="$(ip route |awk '/default/ {print $3}')"

    ip route | grep -qFe "$network" ||
        ip route add to "$network" via "$gw" dev eth0
    iptables -A OUTPUT --destination "$network" -j ACCEPT
    [[ -e $route ]] && grep -q "^$network\$" "$route" || echo "$network" >>"$route"
}

### vpn: setup openvpn client
# Arguments:
#   server) VPN GW server
#   user) user name on VPN
#   pass) password on VPN
#   port) port to connect to VPN (optional)
# Return: configured .ovpn file
vpn() { local server user pass port i pem
    server="$1"
    user="$2"
    pass="$3"
    port="${4:-1194}"
    pem="$(command ls "$dir"/*.pem 2>&-)"

    {
        echo "client"
        echo "dev tun"
        echo "proto udp"
        # shellcheck disable=SC2013
        for i in $(sed 's/:/ /g' <<< "$server"); do
            echo "remote $i $port"
        done
        [[ $server =~ : ]] && echo "remote-random"
        echo "resolv-retry infinite"
        echo "keepalive 10 60"
        echo "nobind"
        echo "persist-key"
        echo "persist-tun"
        [[ "${CIPHER:-""}" ]] && echo "cipher $CIPHER"
        [[ "${AUTH:-""}" ]] && echo "auth $AUTH"
        echo "tls-client"
        echo "remote-cert-tls server"
        echo "auth-user-pass $auth"
        echo "comp-lzo"
        echo "verb 1"
        echo "reneg-sec 0"
        echo "redirect-gateway def1"
        echo "disable-occ"
        echo "fast-io"
        echo "ca $cert"
        [[ $(wc -w <<< $pem) -eq 1 ]] && echo "crl-verify $pem"
    } > "$conf"

    {
        echo "$user"
        echo "$pass"
    } > "$auth"
    chmod 0600 "$auth"

    [[ "${FIREWALL:-""}" || -e $route6 || -e $route ]] &&
        [[ "${4:-""}" ]] && firewall "$port"
}

### vpnportforward: setup vpn port forwarding
# Arguments:
#   port) forwarded port
# Return: configured NAT rule
vpnportforward() { local port="$1"
    ip6tables -t nat -A OUTPUT -p tcp --dport "$port" -j DNAT \
                --to-destination ::11:"$port" 2>/dev/null
    iptables -t nat -A OUTPUT -p tcp --dport "$port" -j DNAT \
                --to-destination 127.0.0.11:"$port"
    echo "Setup forwarded port: $port"
}

### usage: Help
# Arguments:
#   none)
# Return: Help text
usage() { local RC="${1:-0}"
    echo "Usage: ${0##*/} [-opt] [command]
Options (fields in '[]' are optional, '<>' are required):
    -h          This help
    -c '<passwd>' Configure an authentication password to open the cert
                required arg: '<passwd>'
                <passwd> password to access the certificate file
    -d          Use the VPN provider's DNS resolvers
    -f '[port]' Firewall rules so that only the VPN and DNS are allowed to
                send internet traffic (IE if VPN is down it's offline)
                optional arg: [port] to use, instead of default
    -p '<port>' Forward port <port>
                  required arg: '<port>'
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
" >&2
    exit "$RC"
}

dir="/vpn"
auth="$dir/vpn.cert_auth"
conf="$dir/vpn.conf"
cert="$dir/vpn-ca.crt"
route="$dir/.firewall"
route6="$dir/.firewall6"
[ -f "$conf" ] || {
    [ "$(command find "$dir"/ -maxdepth 1 -iname '*.ovpn' -or -iname '*.conf' 2>/dev/null | wc -l)" == "1" ] &&
        conf="$(command find "$dir"/ -maxdepth 1 -iname '*.ovpn' -or -iname '*.conf' 2>/dev/null)"
}
[ -f "$cert" ] || {
    [ "$(command find "$dir"/ -maxdepth 1 -iname '*.cert' -or -iname '*.crt' 2>/dev/null | wc -l)" == "1" ] &&
        cert="$(command find "$dir"/ -maxdepth 1 -iname '*.cert' -or -iname '*.crt' 2>/dev/null)"
}

while getopts ":hc:df:p:R:r:v:" opt; do
    case "$opt" in
        h) usage ;;
        c) cert_auth "$OPTARG" ;;
        d) DNS=true ;;
        f) firewall "$OPTARG"; touch $route $route6 ;;
        p) vpnportforward "$OPTARG" ;;
        R) return_route6 "$OPTARG" ;;
        r) return_route "$OPTARG" ;;
        v) eval vpn "$(sed 's/^/"/; s/$/"/; s/;/" "/g' <<< $OPTARG)" ;;
        "?") echo "Unknown option: -$OPTARG"; usage 1 ;;
        ":") echo "No argument value for option: -$OPTARG"; usage 2 ;;
    esac
done
shift $(( OPTIND - 1 ))

[[ "${CERT_AUTH:-""}" ]] && cert_auth "$CERT_AUTH"
[[ "${FIREWALL:-""}" || -e $route ]] && firewall "${FIREWALL:-""}"
[[ "${ROUTE6:-""}" ]] && return_route6 "$ROUTE6"
[[ "${ROUTE:-""}" ]] && return_route "$ROUTE"
[[ "${VPN:-""}" ]] && eval vpn "$(sed 's/^/"/; s/$/"/; s/;/" "/g' <<< $VPN)"
[[ "${DNS:-""}" ]] && dns
[[ "${VPNPORT:-""}" ]] && vpnportforward "$VPNPORT"
[[ "${GROUPID:-""}" =~ ^[0-9]+$ ]] && groupmod -g "$GROUPID" -o vpn

if [[ $# -ge 1 && -x $(which "$1" 2>&-) ]]; then
    exec "$@"
elif [[ $# -ge 1 ]]; then
    echo "ERROR: command not found: $1"
    exit 13
elif ps -ef | egrep -v 'grep|openvpn.sh' | grep -q openvpn; then
    echo "Service already running, please restart container to apply changes"
else
    mkdir -p /dev/net
    [[ -c /dev/net/tun ]] || mknod -m 0666 /dev/net/tun c 10 200
    [[ -e $conf ]] || { echo "ERROR: VPN not configured!"; sleep 120; }
    [[ -e $cert ]] || grep -q '<ca>' "$conf" ||
        { echo "ERROR: VPN CA cert missing!"; sleep 120; }
    exec sg vpn -c "openvpn --cd '$dir' --config '$conf'"
fi
