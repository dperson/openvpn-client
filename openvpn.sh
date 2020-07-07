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
# Return: openvpn argument to support certificate authentication
cert_auth() { local passwd="$1"
    grep -q "^${passwd}\$" $cert_auth || {
        echo "$passwd" >$cert_auth
    }
    chmod 0600 $cert_auth
}

### dns: setup openvpn client DNS
# Arguments:
#   none)
# Return: openvpn arguments to use VPN provider's DNS resolvers
dns() {
    ext_args+=" --up /etc/openvpn/up.sh"
    ext_args+=" --down /etc/openvpn/down.sh"
}

### firewall: firewall all output not DNS/VPN that's not over the VPN connection
# Arguments:
#   port) optional port that will be used to connect to VPN (should auto detect)
# Return: configured firewall
firewall() { local port="${1:-1194}" docker_network="$(ip -o addr show dev eth0|
            awk '$3 == "inet" {print $4}')" \
            docker6_network="$(ip -o addr show dev eth0 |
            awk '$3 == "inet6" {print $4; exit}')"
    [[ -z "${1:-}" && -r $conf ]] &&
        port="$(awk -F"[\r\t ]+" '/^remote/ && $3~/^[0-9]+$/ {print $3}' $conf |
                    uniq | grep ^ || echo 1194)"

    test -f /proc/net/if_inet6 && { lsmod |grep -qF ip6table_filter || { \
        echo "WARNING: ip6tables disabled!"
        echo "Run 'sudo modprobe ip6table_filter' on your host"; };}

    ip6tables -F 2>/dev/null
    ip6tables -X 2>/dev/null
    ip6tables -P INPUT DROP 2>/dev/null
    ip6tables -P FORWARD DROP 2>/dev/null
    ip6tables -P OUTPUT DROP 2>/dev/null
    ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT \
                2>/dev/null
    ip6tables -A INPUT -p icmp -j ACCEPT 2>/dev/null
    ip6tables -A INPUT -i lo -j ACCEPT 2>/dev/null
    ip6tables -A INPUT -s ${docker6_network} -j ACCEPT 2>/dev/null
    ip6tables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT \
                2>/dev/null
    ip6tables -A FORWARD -p icmp -j ACCEPT 2>/dev/null
    ip6tables -A FORWARD -i lo -j ACCEPT 2>/dev/null
    ip6tables -A FORWARD -d ${docker6_network} -j ACCEPT 2>/dev/null
    ip6tables -A FORWARD -s ${docker6_network} -j ACCEPT 2>/dev/null
    ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT \
                2>/dev/null
    ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null
    ip6tables -A OUTPUT -o tap+ -j ACCEPT 2>/dev/null
    ip6tables -A OUTPUT -o tun+ -j ACCEPT 2>/dev/null
    ip6tables -A OUTPUT -d ${docker6_network} -j ACCEPT 2>/dev/null
    ip6tables -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null &&
    ip6tables -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null||{
        for i in $port; do
            ip6tables -A OUTPUT -p tcp -m tcp --dport $i -j ACCEPT 2>/dev/null
            ip6tables -A OUTPUT -p udp -m udp --dport $i -j ACCEPT 2>/dev/null
        done
        ip6tables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT 2>/dev/null; }
    ip6tables -t nat -A POSTROUTING -o tap+ -j MASQUERADE
    ip6tables -t nat -A POSTROUTING -o tun+ -j MASQUERADE
    iptables -F
    iptables -X
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -s ${docker_network} -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i lo -j ACCEPT
    iptables -A FORWARD -d ${docker_network} -j ACCEPT
    iptables -A FORWARD -s ${docker_network} -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -o tap+ -j ACCEPT
    iptables -A OUTPUT -o tun+ -j ACCEPT
    iptables -A OUTPUT -d ${docker_network} -j ACCEPT
    iptables -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null &&
    iptables -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT || {
        for i in $port; do
            iptables -A OUTPUT -p tcp -m tcp --dport $i -j ACCEPT
            iptables -A OUTPUT -p udp -m udp --dport $i -j ACCEPT
        done
        iptables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT; }
    if grep -Fq "127.0.0.11" /etc/resolv.conf; then
        iptables -A OUTPUT -d 127.0.0.11 -m owner --gid-owner vpn -j ACCEPT \
        2>/dev/null && {
            iptables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
            ext_args+=" --route-up '/bin/sh -c \""
            ext_args+=" iptables -A OUTPUT -d 127.0.0.11 -j ACCEPT\"'"
            ext_args+=" --route-pre-down '/bin/sh -c \""
            ext_args+=" iptables -D OUTPUT -d 127.0.0.11 -j ACCEPT\"'"
        } || iptables -A OUTPUT -d 127.0.0.11 -j ACCEPT; fi
    iptables -t nat -A POSTROUTING -o tap+ -j MASQUERADE
    iptables -t nat -A POSTROUTING -o tun+ -j MASQUERADE
    [[ -r $firewall_cust ]] && . $firewall_cust
    for i in $route6 $route; do [[ -e $i ]] || touch $i; done
    [[ -s $route6 ]] && for net in $(cat $route6); do return_route6 $net; done
    [[ -s $route ]] && for net in $(cat $route); do return_route $net; done
}

### global_return_routes: add a route back to all networks for return traffic
# Arguments:
#   none)
# Return: configured return routes
global_return_routes() { local if=$(ip r | awk '/^default/ {print $5; quit}')
    local gw6="$(ip -6 r show dev $if | awk '/default/ {print $3}')" \
    gw="$(ip -4 r show dev $if | awk '/default/ {print $3}')" \
    ip6=$(ip -6 a show dev $if | awk -F '[ \t/]+' '/inet6.*global/ {print $3}')\
    ip=$(ip -4 a show dev $if | awk -F '[ \t/]+' '/inet .*global/ {print $3}')

    for i in $ip6; do
        ip -6 rule show table 10 | grep -q "$i\\>" ||
            ip -6 rule add from $i lookup 10
        ip6tables -S 2>/dev/null | grep -q "$i\\>" ||
            ip6tables -A INPUT -d $i -j ACCEPT 2>/dev/null
    done
    for i in $gw6; do
        ip -6 route show table 10 | grep -q "$i\\>" ||
            ip -6 route add default via $i table 10
    done

    for i in $ip; do
        ip -4 rule show table 10 | grep -q "$i\\>" ||
            ip rule add from $i lookup 10
        iptables -S | grep -q "$i\\>" || iptables -A INPUT -d $i -j ACCEPT
    done
    for i in $gw; do
        ip -4 route show table 10 | grep -q "$i\\>" ||
            ip route add default via $i table 10
    done
}

### return_route: add a route back to your network, so that return traffic works
# Arguments:
#   network) a CIDR specified network range
# Return: configured return route
return_route6() { local network="$1" gw="$(ip -6 route |
                awk '/default/ {print $3}')"
    echo "The use of ROUTE6 or -R may no longer be needed, try it without!!"
    ip -6 route | grep -q "$network" ||
        ip -6 route add to $network via $gw dev eth0
    ip6tables -A INPUT -s $network -j ACCEPT 2>/dev/null
    ip6tables -A FORWARD -d $network -j ACCEPT 2>/dev/null
    ip6tables -A FORWARD -s $network -j ACCEPT 2>/dev/null
    ip6tables -A OUTPUT -d $network -j ACCEPT 2>/dev/null
    [[ -e $route6 ]] &&grep -q "^$network\$" $route6 ||echo "$network" >>$route6
}

### return_route: add a route back to your network, so that return traffic works
# Arguments:
#   network) a CIDR specified network range
# Return: configured return route
return_route() { local network="$1" gw="$(ip route |awk '/default/ {print $3}')"
    echo "The use of ROUTE or -r may no longer be needed, try it without!"
    ip route | grep -q "$network" ||
        ip route add to $network via $gw dev eth0
    iptables -A INPUT -s $network -j ACCEPT
    iptables -A FORWARD -d $network -j ACCEPT
    iptables -A FORWARD -s $network -j ACCEPT
    iptables -A OUTPUT -d $network -j ACCEPT
    [[ -e $route ]] && grep -q "^$network\$" $route || echo "$network" >>$route
}

### vpn_auth: configure authentication username and password
# Arguments:
#   user) user name on VPN
#   pass) password on VPN
# Return: configured auth file
vpn_auth() { local user="$1" pass="$2"
    echo "$user" >$auth
    echo "$pass" >>$auth
    chmod 0600 $auth
}

### vpn: setup openvpn client
# Arguments:
#   server) VPN GW server
#   user) user name on VPN
#   pass) password on VPN
#   port) port to connect to VPN (optional)
#   proto) protocol to connect to VPN (optional)
# Return: configured .ovpn file
vpn() { local server="$1" user="$2" pass="$3" port="${4:-1194}" proto=${5:-udp}\
            i pem="$(\ls $dir/*.pem 2>&-)"

    echo "client" >$conf
    echo "dev tun" >>$conf
    echo "proto $proto" >>$conf
    for i in $(sed 's/:/ /g' <<< $server); do
        echo "remote $i $port" >>$conf
    done
    [[ $server =~ : ]] && echo "remote-random" >>$conf
    echo "resolv-retry infinite" >>$conf
    echo "keepalive 10 60" >>$conf
    echo "nobind" >>$conf
    echo "persist-key" >>$conf
    echo "persist-tun" >>$conf
    [[ "${CIPHER:-}" ]] && echo "cipher $CIPHER" >>$conf
    [[ "${AUTH:-}" ]] && echo "auth $AUTH" >>$conf
    echo "tls-client" >>$conf
    echo "remote-cert-tls server" >>$conf
    echo "comp-lzo" >>$conf
    echo "verb 1" >>$conf
    echo "reneg-sec 0" >>$conf
    echo "disable-occ" >>$conf
    echo "fast-io" >>$conf
    echo "ca $cert" >>$conf
    [[ $(wc -w <<< $pem) -eq 1 ]] && echo "crl-verify $pem" >>$conf

    vpn_auth "$user" "$pass"

    [[ "${FIREWALL:-}" || -e $route6 || -e $route ]] &&
        [[ "${4:-}" ]] && firewall $port
}

### vpnportforward: setup vpn port forwarding
# Arguments:
#   port) forwarded port
#   protocol) optional protocol (defaults to TCP)
# Return: configured NAT rule
vpnportforward() { local port="$1" protocol="${2:-tcp}"
    ip6tables -A INPUT -p $protocol -m $protocol --dport $port -j ACCEPT \
                2>/dev/null
    iptables -A INPUT -p $protocol -m $protocol --dport $port -j ACCEPT
    echo "Setup forwarded port: $port $protocol"
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
    -a '<user;password>' Configure authentication username and password
    -D          Don't use the connection as the default route
    -d          Use the VPN provider's DNS resolvers
    -f '[port]' Firewall rules so that only the VPN and DNS are allowed to
                send internet traffic (IE if VPN is down it's offline)
                optional arg: [port] to use, instead of default
    -m '<mss>'  Maximum Segment Size <mss>
                required arg: '<mss>'
    -o '<args>' Allow to pass any arguments directly to openvpn
                required arg: '<args>'
                <args> could be any string matching openvpn arguments
                i.e '--arg1 value --arg2 value'
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
                optional args:
                [port] to use, instead of default
                [proto] to use, instead of udp (IE, tcp)

The 'command' (if provided and valid) will be run instead of openvpn
" >&2
    exit $RC
}

dir="/vpn"
auth="$dir/vpn.auth"
cert_auth="$dir/vpn.cert_auth"
conf="$dir/vpn.conf"
cert="$dir/vpn-ca.crt"
firewall_cust="$dir/.firewall_cust"
route="$dir/.firewall"
route6="$dir/.firewall6"
export ext_args="--script-security 2 --redirect-gateway def1"
[[ -f $conf ]] || { [[ $(ls -d $dir/*|egrep '\.(conf|ovpn)$' 2>&-|wc -w) -eq 1 \
            ]] && conf="$(ls -d $dir/* | egrep '\.(conf|ovpn)$' 2>&-)"; }
[[ -f $cert ]] || { [[ $(ls -d $dir/* | egrep '\.ce?rt$' 2>&- | wc -w) -eq 1 \
            ]] && cert="$(ls -d $dir/* | egrep '\.ce?rt$' 2>&-)"; }

while getopts ":hc:Ddf:a:m:o:p:R:r:v:" opt; do
    case "$opt" in
        h) usage ;;
        a) VPN_AUTH="$OPTARG" ;;
        c) CERT_AUTH="$OPTARG" ;;
        D) DEFAULT_GATEWAY="false" ;;
        d) DNS="true" ;;
        f) FIREWALL="$OPTARG" ;;
        m) MSS="$OPTARG" ;;
        o) OTHER_ARGS+=" $OPTARG" ;;
        p) export VPNPORT$OPTIND="$OPTARG" ;;
        R) return_route6 "$OPTARG" ;;
        r) return_route "$OPTARG" ;;
        v) VPN="$OPTARG" ;;
        "?") echo "Unknown option: -$OPTARG"; usage 1 ;;
        ":") echo "No argument value for option: -$OPTARG"; usage 2 ;;
    esac
done
shift $(( OPTIND - 1 ))

[[ "${CERT_AUTH:-}" ]] && cert_auth "$CERT_AUTH"
[[ "${DNS:-}" ]] && dns
[[ "${GROUPID:-}" =~ ^[0-9]+$ ]] && groupmod -g $GROUPID -o vpn
[[ ! -z "${FIREWALL+x}" || -e $route6 || -e $route ]] &&firewall "${FIREWALL:-}"
while read i; do
    return_route6 "$i"
done < <(env | awk '/^ROUTE6[=_]/ {sub (/^[^=]*=/, "", $0); print}')
while read i; do
    return_route "$i"
done < <(env | awk '/^ROUTE[=_]/ {sub (/^[^=]*=/, "", $0); print}')
[[ "${VPN_AUTH:-}" ]] &&
    eval vpn_auth $(sed 's/^/"/; s/$/"/; s/;/" "/g' <<< $VPN_AUTH)
[[ "${VPN_FILES:-}" ]] && { [[ -e $dir/$(cut -d';' -f1 <<< $VPN_FILES) ]] &&
                conf=$dir/$(cut -d';' -f1 <<< $VPN_FILES)
    [[ -e $dir/$(cut -d';' -f2 <<< $VPN_FILES) ]] &&
                cert=$dir/$(cut -d';' -f2 <<< $VPN_FILES); }
[[ "${VPN:-}" ]] && eval vpn $(sed 's/^/"/; s/$/"/; s/;/" "/g' <<< $VPN)
while read i; do
    eval vpnportforward $(sed 's/^/"/; s/$/"/; s/;/" "/g' <<< $i)
done < <(env | awk '/^VPNPORT[0-9=_]/ {sub (/^[^=]*=/, "", $0); print}')

global_return_routes

[[ ${DEFAULT_GATEWAY:-} == "false" ]] &&
            ext_args=$(sed 's/ --redirect-gateway def1//' <<< $ext_args)
[[ -e $auth ]] && ext_args+=" --auth-user-pass $auth"
[[ -e $cert_auth ]] && ext_args+=" --askpass $cert_auth"

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
    [[ -e $cert ]] || grep -Eq '^ *(<ca>|ca +)' $conf ||
        { echo "ERROR: VPN CA cert missing!"; sleep 120; }
    set -x
    exec sg vpn -c "openvpn --cd $dir --config $conf $ext_args \
               ${OTHER_ARGS:-} ${MSS:+--fragment $MSS --mssfix}"
fi