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

dir="/vpn"
auth="$dir/vpn.cert_auth"
conf="$dir/vpn.conf"
cert="$dir/vpn-ca.crt"
file="$dir/.firewall"
[[ -f $conf ]] || { [[ $(ls $dir/*.{conf,ovpn} 2>&- | wc -w) -eq 1 ]] &&
            conf=$(ls $dir/*.{conf,ovpn} 2>&-); }
[[ -f $cert ]] || { [[ $(ls $dir/*.crt 2>&- | wc -w) -eq 1 ]] &&
            cert=$(ls $dir/*.crt 2>&-); }

### cert_auth: setup auth passwd for accessing certificate
# Arguments:
#   passwd) Password to access the cert
# Return: conf file that uses VPN provider's DNS resolvers
cert_auth() { local passwd="$1"
    grep -q "^${passwd}\$" $auth || {
        echo "$passwd" >$auth
    }
    chmod 0600 $auth
    grep -q "^askpass ${auth}\$" $conf || {
        sed -i '/askpass/d' $conf
        echo "askpass $auth" >>$conf
    }
}

### dns: setup openvpn client DNS
# Arguments:
#   none)
# Return: conf file that uses VPN provider's DNS resolvers
dns() {
    sed -i '/resolv-*conf/d; /script-security/d' $conf
    echo "# This updates the resolvconf with dns settings" >>$conf
    echo "script-security 2" >>$conf
    echo "up /etc/openvpn/update-resolv-conf" >>$conf
    echo "down /etc/openvpn/update-resolv-conf" >>$conf
}

### firewall: firewall all output not DNS/VPN that's not over the VPN connection
# Arguments:
#   none)
# Return: configured firewall
firewall() { local port=${1:-1194} docker_network=$(ip -o addr show dev eth0 |
            awk '$3 == "inet" {print $4}') network
    [[ -z "${1:-""}" && -r $conf ]] &&
        port=$(awk '/^remote / && NF ~ /^[0-9]*$/ {print $NF}' $conf |
                    grep ^ || echo 1194)

    iptables -F OUTPUT
    iptables -P OUTPUT DROP
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -o tap0 -j ACCEPT
    iptables -A OUTPUT -o tun0 -j ACCEPT
    iptables -A OUTPUT -d ${docker_network} -j ACCEPT
    iptables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null &&
    iptables -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT || {
        iptables -A OUTPUT -p tcp -m tcp --dport $port -j ACCEPT
        iptables -A OUTPUT -p udp -m udp --dport $port -j ACCEPT; }
    [[ -s $file ]] && for network in $(cat $file); do return_route $network;done
}

### return_route: add a route back to your network, so that return traffic works
# Arguments:
#   network) a CIDR specified network range
# Return: configured return route
return_route() { local network="$1" gw=$(ip route | awk '/default/ {print $3}')
    ip route | grep -q "$network" ||
        ip route add to $network via $gw dev eth0
    [[ -e $file ]] && iptables -A OUTPUT --destination $network -j ACCEPT
    [[ -e $file ]] && grep -q "^$network\$" $file || echo "$network" >>$file
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
#   port) port to connect to VPN (optional)
# Return: configured .ovpn file
vpn() { local server="$1" user="$2" pass="$3" port="${4:-1194}" i \
            pem=$(\ls $dir/*.pem 2>&-)

    echo "client" >$conf
    echo "dev tun" >>$conf
    echo "proto udp" >>$conf
    for i in $(sed 's/:/ /g' <<< $server); do
        echo "remote $i $port" >>$conf
    done
    [[ $server =~ : ]] && echo "remote-random" >>$conf
    echo "resolv-retry infinite" >>$conf
    echo "keepalive 10 30" >>$conf
    echo "nobind" >>$conf
    echo "persist-key" >>$conf
    [[ "${CIPHER:-""}" ]] && echo "cipher $CIPHER" >>$conf
    [[ "${AUTH:-""}" ]] && echo "auth $AUTH" >>$conf
    echo "tls-client" >>$conf
    echo "remote-cert-tls server" >>$conf
    echo "auth-user-pass $auth" >>$conf
    echo "comp-lzo" >>$conf
    echo "verb 1" >>$conf
    echo "reneg-sec 0" >>$conf
    echo "ca $cert" >>$conf
    [[ $(wc -w <<< $pem) -eq 1 ]] && echo "crl-verify $pem" >>$conf
    echo "redirect-gateway def1" >>$conf

    echo "$user" >$auth
    echo "$pass" >>$auth
    chmod 0600 $auth

    [[ "${FIREWALL:-""}" || -e $file ]] && [[ "${4:-""}" ]] && firewall $port
}

### vpnportforward: setup vpn port forwarding
# Arguments:
#   port) forwarded port
# Return: configured NAT rule
vpnportforward() { local port="$1"
    iptables -t nat -A OUTPUT -p tcp --dport $port -j DNAT \
                --to-destination 127.0.0.11:$port
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
    -c '<passwd>' Configure an authentication password to open the cert
                required arg: '<passwd>'
                <passwd> password to access the certificate file
    -d          Use the VPN provider's DNS resolvers
    -f '[port]' Firewall rules so that only the VPN and DNS are allowed to
                send internet traffic (IE if VPN is down it's offline)
                optional arg: [port] to use, instead of default
    -p '<port>' Forward port <port>
                  required arg: '<port>'
    -r '<network>' CIDR network (IE 192.168.1.0/24)
                required arg: '<network>'
                <network> add a route to (allows replies once the VPN is up)
    -t ''       Configure timezone
                optionalarg: '[timezone]' - zoneinfo timezone for container
    -v '<server;user;password[;port]>' Configure OpenVPN
                required arg: '<server>;<user>;<password>'
                <server> to connect to (multiple servers are separated by :)
                <user> to authenticate as
                <password> to authenticate with
                optional arg: [port] to use, instead of default

The 'command' (if provided and valid) will be run instead of openvpn
" >&2
    exit $RC
}

while getopts ":hc:df:p:r:t:v:" opt; do
    case "$opt" in
        h) usage ;;
        c) cert_auth "$OPTARG" ;;
        d) DNS=true ;;
        f) firewall "$OPTARG"; touch $file ;;
        p) vpnportforward "$OPTARG" ;;
        r) return_route "$OPTARG" ;;
        t) timezone "$OPTARG" ;;
        v) eval vpn $(sed 's/^\|$/"/g; s/;/" "/g' <<< $OPTARG) ;;
        "?") echo "Unknown option: -$OPTARG"; usage 1 ;;
        ":") echo "No argument value for option: -$OPTARG"; usage 2 ;;
    esac
done
shift $(( OPTIND - 1 ))

[[ "${CERT_AUTH:-""}" ]] && cert_auth "$CERT_AUTH"
[[ "${FIREWALL:-""}" || -e $file ]] && firewall "${FIREWALL:-""}"
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
    mkdir -p /dev/net
    [[ -c /dev/net/tun ]] || mknod -m 0666 /dev/net/tun c 10 200
    [[ -e $conf ]] || { echo "ERROR: VPN not configured!"; sleep 120; }
    [[ -e $cert ]] || grep -q '<ca>' $conf ||
        { echo "ERROR: VPN CA cert missing!"; sleep 120; }
    exec sg vpn -c "openvpn --config $conf"
fi