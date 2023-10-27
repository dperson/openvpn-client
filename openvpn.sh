#!/usr/bin/env bash

set -x

set -euo pipefail  # Makes the script exit on any command failure and treats unset variables as an error
set -o nounset                              # Treat unset variables as an error

# Global variables
declare dir="/vpn"
declare auth="$dir/vpn.auth"
declare cert_auth="$dir/vpn.cert_auth"
declare conf="$dir/vpn.conf"
declare cert="$dir/vpn-ca.crt"
declare firewall_cust="$dir/.firewall_cust"
declare route="$dir/.firewall"
declare route6="$dir/.firewall6"
declare ext_args="--script-security 2 --redirect-gateway def1"

### cert_auth: setup auth passwd for accessing certificate
# Arguments:
#   passwd) Password to access the cert
# Return: openvpn argument to support certificate authentication
cert_auth() {
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
firewall() {
    # Define configuration and routing files
    local conf="/etc/openvpn/openvpn.conf"
    local firewall_cust="/etc/openvpn/firewall_cust.sh"
    local route="/etc/openvpn/route"
    local route6="/etc/openvpn/route6"

    # Define default port
    local port="${1:-1194}"

    # Gather 'eth' interfaces
    local ethers=$(ls /sys/class/net/ | grep '^eth')

    # Initialize arrays to store IP addresses from all 'eth' interfaces
    declare -a docker_networks
    declare -a docker6_networks

    # Populate the arrays
    for iface in $ethers; do
        docker_networks+=( "$(ip -o addr show dev "$iface" | awk '$3 == "inet" {print $4}')" )
        docker6_networks+=( "$(ip -o addr show dev "$iface" | awk '$3 == "inet6" {print $4; exit}')" )
    done

    # Check for custom port in the configuration file
    [[ -z "${1:-}" && -r $conf ]] &&
        port=$(awk -F"[\r\t ]+" '/^remote/ && $3~/^[0-9]+$/ {print $3}' "$conf" | uniq | grep -E '^[0-9]+$' || echo 1194)

    # Setup IPv6 iptables
    ip6tables -F 2>/dev/null
    ip6tables -X 2>/dev/null
    ip6tables -P INPUT DROP 2>/dev/null
    ip6tables -P FORWARD DROP 2>/dev/null
    ip6tables -P OUTPUT DROP 2>/dev/null

    # Common rules for IPv6
    ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    ip6tables -A INPUT -p icmpv6 -j ACCEPT 2>/dev/null  # Updated for IPv6 ICMP
    ip6tables -A INPUT -i lo -j ACCEPT 2>/dev/null

    # Rules for each IPv6 address
    for docker6_network in "${docker6_networks[@]}"; do
        if [[ -n $docker6_network ]]; then
            ip6tables -A INPUT -s "$docker6_network" -j ACCEPT 2>/dev/null
            ip6tables -A FORWARD -d "$docker6_network" -j ACCEPT 2>/dev/null
            ip6tables -A FORWARD -s "$docker6_network" -j ACCEPT 2>/dev/null
            ip6tables -A OUTPUT -d "$docker6_network" -j ACCEPT 2>/dev/null
        fi
    done

    # Additional common rules for FORWARD and OUTPUT for IPv6, if any, should be added here...

    # Setup IPv4 iptables
    iptables -F
    iptables -X

    # Common rules for IPv4
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT

    # Rules for each IPv4 address
    for docker_network in "${docker_networks[@]}"; do
        if [[ -n $docker_network ]]; then
            iptables -A INPUT -s "$docker_network" -j ACCEPT
            iptables -A FORWARD -d "$docker_network" -j ACCEPT
            iptables -A FORWARD -s "$docker_network" -j ACCEPT
            iptables -A OUTPUT -d "$docker_network" -j ACCEPT
        fi
    done

    # Allow traffic to VPN servers
    for server in "${vpn_servers[@]}"; do
        iptables -A OUTPUT -d "$server" -j ACCEPT
    done

    # Allow traffic to DNS servers
    for server in "${dns_servers[@]}"; do
        iptables -A OUTPUT -d "$server" -j ACCEPT
    done

    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP
    # Additional common rules for OUTPUT and NAT tables for IPv4, if any, should be added here...


    # Check if custom firewall rules file exists and source it
    if [[ -r $firewall_cust ]]; then
        . $firewall_cust
    fi

    # Ensure routing files exist and process their contents
    for i in $route6 $route; do
        if [[ ! -e $i ]]; then
            touch $i
        fi

        if [[ -s $i ]]; then
            while IFS= read -r net; do
                # Define your return_route6 and return_route functions somewhere in your script.
                # They should handle adding the necessary routes.
                [[ $i == "$route6" ]] && return_route6 "$net"
                [[ $i == "$route" ]] && return_route "$net"
            done < "$i"
        fi
    done
}


### global_return_routes: Add routes back to all networks for return traffic.
# Arguments:
#   None
# Returns: Configured return routes
global_return_routes() {
    # Fetch the primary network interface used for the default route.
    local iface=$(ip route | awk '/^default/ {print $5; exit}')

    # Extract default gateways and local IPs using the 'ip' command.
    local gw6=$(ip -6 route show dev "$iface" | awk '/default/ {print $3}')
    local gw=$(ip -4 route show dev "$iface" | awk '/default/ {print $3}')
    local ip6=$(ip -6 addr show dev "$iface" | awk -F '[ \t/]+' '/inet6.*global/ {print $3}')
    local ip=$(ip -4 addr show dev "$iface" | awk -F '[ \t/]+' '/inet .*global/ {print $3}')

    # Process IPv6 addresses and default gateways.
    for addr in $ip6; do
        ip -6 rule show table 10 | grep -q "$addr\\>" || ip -6 rule add from $addr lookup 10
        ip6tables -S 2>/dev/null | grep -q "$addr\\>" || ip6tables -A INPUT -d $addr -j ACCEPT 2>/dev/null
    done

    for gateway in $gw6; do
        ip -6 route show table 10 | grep -q "$gateway\\>" || ip -6 route add default via $gateway table 10
    done

    # Process IPv4 addresses and default gateways.
    for addr in $ip; do
        ip rule show table 10 | grep -q "$addr\\>" || ip rule add from $addr lookup 10
        iptables -S | grep -q "$addr\\>" || iptables -A INPUT -d $addr -j ACCEPT
    done

    for gateway in $gw; do
        ip route show table 10 2>/dev/null | grep -q "$gateway\\>" || ip route add default via $gateway table 10
    done
}

### return_route6: Add a route back to your IPv6 network, ensuring return traffic.
# Arguments:
#   1) Network in CIDR format
# Returns: Configured return route
return_route6() {
    local network="$1"

    # Check if the network variable is set, else return with an error.
    if [[ -z "$network" ]]; then
        echo "Error: Network block (in CIDR notation) must be specified."
        return 1
    fi

    # Fetch the default gateway for IPv6.
    local gw=$(ip -6 route | awk '/default/ {print $3; exit}')

    echo "Note: The use of ROUTE6 or -R flags might be unnecessary. Consider trying without them."

    # Check whether the route already exists, and add it if absent.
    ip -6 route | grep -q "$network" || ip -6 route add to "$network" via "$gw" dev eth0

    # Update ip6tables rules to accept traffic from the specified network.
    ip6tables -A INPUT -s "$network" -j ACCEPT 2>/dev/null
    ip6tables -A FORWARD -d "$network" -j ACCEPT 2>/dev/null
    ip6tables -A FORWARD -s "$network" -j ACCEPT 2>/dev/null
    ip6tables -A OUTPUT -d "$network" -j ACCEPT 2>/dev/null

    # Append the network to the route6 file if it doesn't already exist there.
    local route6="/path/to/route6_file"  # Specify the correct path for your route6 file.
    if [[ -e $route6 ]]; then
        grep -q "^$network\$" "$route6" || echo "$network" >> "$route6"
    else
        echo "Error: '$route6' does not exist."
    fi
}

### return_route: Add a route back to your IPv4 network, ensuring return traffic.
# Arguments:
#   1) Network in CIDR format
# Returns: Configured return route
return_route() {
    local network="$1"

    # Check if the network variable is set, else return with an error.
    if [[ -z "$network" ]]; then
        echo "Error: Network block (in CIDR notation) must be specified."
        return 1
    fi

    # Fetch the default gateway for IPv4.
    local gw=$(ip route | awk '/default/ {print $3; exit}')

    echo "Note: The use of ROUTE or -r flags might be unnecessary. Consider trying without them."

    # Check whether the route already exists, and add it if absent.
    ip route | grep -q "$network" || ip route add to "$network" via "$gw" dev eth0

    # Update iptables rules to accept traffic from the specified network.
    iptables -A INPUT -s "$network" -j ACCEPT
    iptables -A FORWARD -d "$network" -j ACCEPT
    iptables -A FORWARD -s "$network" -j ACCEPT
    iptables -A OUTPUT -d "$network" -j ACCEPT

    # Append the network to the route file if it doesn't already exist there.
    local route="/path/to/route_file"  # Specify the correct path for your route file.
    if [[ -e $route ]]; then
        grep -q "^$network\$" "$route" || echo "$network" >> "$route"
    else
        echo "Error: '$route' does not exist."
    fi
}

#!/bin/bash

### vpn_auth: Configure VPN authentication username and password.
# Arguments:
#   1) Username for VPN
#   2) Password for VPN
# Return: Configures auth file with restricted permissions.
vpn_auth() {
    local user="$1"
    local pass="$2"

    # Validate input parameters.
    if [[ -z "$user" || -z "$pass" ]]; then
        echo "Error: Username and password must be provided."
        return 1
    fi

    # Write credentials to auth file and restrict file permissions.
    {
        echo "$user"
        echo "$pass"
    } > "$auth"
    chmod 0600 "$auth" || { echo "Error: Failed to set permissions on auth file."; return 1; }
}

### vpn: Setup OpenVPN client configuration.
# Arguments:
#   1) VPN server gateway
#   2) Username for VPN
#   3) Password for VPN
#   4) Port to connect to VPN (optional, default: 1194)
#   5) Protocol to connect to VPN (optional, default: udp)
# Return: Creates a configured .ovpn file.
vpn() {
    local server="$1"
    local user="$2"
    local pass="$3"
    local port="${4:-1194}"
    local proto="${5:-udp}"
    local pem_files
    local i

    # Validate required parameters.
    if [[ -z "$server" || -z "$user" || -z "$pass" ]]; then
        echo "Error: Server, username, and password must be provided."
        return 1
    fi

    # Safely fetch the first .pem file.
    pem_files=("$dir"/*.pem)  # Assuming only one is necessary. Add checks if multiple files are possible.
    if (( ${#pem_files[@]} != 1 )); then
        echo "Error: Exactly one .pem file is required in '$dir'."
        return 1
    fi

    # Write the basic configuration to the OpenVPN config file.
    {
        echo "client"
        echo "dev tun"
        echo "proto $proto"
        # Supports multiple servers separated by colons.
        for i in ${server//:/ }; do
            echo "remote $i $port"
        done
        [[ $server == *:* ]] && echo "remote-random"
        echo "resolv-retry infinite"
        echo "keepalive 10 60"
        echo "nobind"
        echo "persist-key"
        echo "persist-tun"
        [[ -n "${CIPHER:-}" ]] && echo "cipher $CIPHER"
        [[ -n "${AUTH:-}" ]] && echo "auth $AUTH"
        echo "tls-client"
        echo "remote-cert-tls server"
        echo "comp-lzo"
        echo "verb 1"
        echo "reneg-sec 0"
        echo "disable-occ"
        echo "fast-io"
        echo "ca $cert"
        echo "crl-verify ${pem_files[0]}"
    } > "$conf"

    # Call the vpn_auth function to set up authentication.
    vpn_auth "$user" "$pass" || { echo "Error: VPN authentication setup failed."; return 1; }

    # If a firewall is needed or routing files exist, invoke the firewall function.
    if [[ -n "${FIREWALL:-}" || -e "$route6" || -e "$route" ]]; then
        # Assuming firewall is a function that takes port as an argument.
        [[ -n "${4:-}" ]] && firewall "$port" || { echo "Error: Firewall setup failed."; return 1; }
    fi
}


# Function to set up VPN port forwarding
vpnportforward() {
    local port="$1"
    local protocol="${2:-tcp}"

    # Check if the rule addition was successful
    if ! iptables -A INPUT -p "$protocol" --dport "$port" -j ACCEPT; then
        echo "Failed to add iptables rule for port: $port $protocol" >&2
        return 1
    fi

    # Add a similar check for ip6tables here if IPv6 is used...

    echo "Setup forwarded port: $port $protocol"
}


# Function to display usage information
usage() {
    local RC="${1:-0}"
    cat >&2 << EOF
Usage: ${0##*/} [OPTION]... [COMMAND]...
Set up and manage the VPN connection.

Options:
    -h             Display this help and exit
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

Example:
  ${0##*/} -v "server;user;password"
EOF
    exit "$RC"
}

# Check for the configuration and certificate files
[[ -f $conf ]] || { [[ $(ls -d $dir/* | grep -E '\.(conf|ovpn)$' 2>&- | wc -w) -eq 1 ]] && conf="$(ls -d $dir/* | grep -E '\.(conf|ovpn)$' 2>&-)"; }
[[ -f $cert ]] || { [[ $(ls -d $dir/* | grep -E '\.ce?rt$' 2>&- | wc -w) -eq 1 ]] && cert="$(ls -d $dir/* | grep -E '\.ce?rt$' 2>&-)"; }

# Parse the OpenVPN config file to extract the 'remote' server addresses
mapfile -t vpn_servers < <(grep -oP '^remote\s+\K[^\s]+' "$conf")

# Parse the OpenVPN config file or the system's resolv.conf to find the DNS server
# This is an example and might need to be adjusted based on your specific setup
mapfile -t dns_servers < <(grep -oP 'dhcp-option\s+DNS\s+\K[^\s]+' "$conf" || grep -oP '^nameserver\s+\K[^\s]+' /etc/resolv.conf)

# Check if we didn't find any DNS servers in the OpenVPN configuration
if [ ${#dns_servers[@]} -eq 0 ]; then
    # No DNS servers were found in the OpenVPN config, let's use the system's DNS settings
    mapfile -t dns_servers < <(grep -oP '^nameserver\s+\K[^\s]+' /etc/resolv.conf)
fi


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
        "?") echo "Unknown option: -$OPTARG" >&2; usage 1 ;;
        ":") echo "No argument value for option: -$OPTARG" >&2; usage 2 ;;
    esac
done
shift $((OPTIND - 1))


# Main script logic starts here

# Certificate authentication
[[ -n "${CERT_AUTH:-}" ]] && cert_auth "$CERT_AUTH"

# DNS configuration
[[ -n "${DNS:-}" ]] && dns

# Group modification
if [[ "${GROUPID:-}" =~ ^[0-9]+$ ]]; then
    groupmod -g "$GROUPID" -o vpn
fi

# Firewall setup
if [[ -n "${FIREWALL:-}" || -e $route6 || -e $route ]]; then
    firewall "${FIREWALL:-}"
fi

# Return route configurations
while IFS= read -r i; do
    return_route6 "$i"
done < <(env | awk '/^ROUTE6[=_]/ {gsub (/^[^=]*=/, "", $0); print}')

while IFS= read -r i; do
    return_route "$i"
done < <(env | awk '/^ROUTE[=_]/ {gsub (/^[^=]*=/, "", $0); print}')

# VPN authentication
if [[ -n "${VPN_AUTH:-}" ]]; then
    eval "vpn_auth $(sed 's/^/"/; s/$/"/; s/;/" "/g' <<< "$VPN_AUTH")"
fi

# VPN file checks and setup
if [[ -n "${VPN_FILES:-}" ]]; then
    local file1 file2
    file1=$dir/$(cut -d';' -f1 <<< "$VPN_FILES")
    file2=$dir/$(cut -d';' -f2 <<< "$VPN_FILES")

    [[ -e $file1 ]] && conf=$file1
    [[ -e $file2 ]] && cert=$file2
fi

# VPN setup
[[ -n "${VPN:-}" ]] && eval "vpn $(sed 's/^/"/; s/$/"/; s/;/" "/g' <<< "$VPN")"

# Port forwarding
while IFS= read -r i; do
    eval "vpnportforward $(sed 's/^/"/; s/$/"/; s/;/" "/g' <<< "$i")"
done < <(env | awk '/^VPNPORT[0-9=_]/ {gsub (/^[^=]*=/, "", $0); print}')

# Global return routes setup (define this function's behavior as required)
global_return_routes

# Adjust external arguments based on various conditions
[[ ${DEFAULT_GATEWAY:-} == "false" ]] && ext_args=$(sed 's/ --redirect-gateway def1//' <<< "$ext_args")
[[ -e $auth ]] && ext_args+=" --auth-user-pass $auth"
[[ -e $cert_auth ]] && ext_args+=" --askpass $cert_auth"

# Command execution and service management logic
if (( $# >= 1 )); then
    if command -v "$1" >/dev/null 2>&1; then
        exec "$@"
    else
        echo "ERROR: command not found: $1" >&2
        exit 13
    fi
elif pgrep -f /usr/sbin/openvpn >/dev/null; then
    echo "Service already running, please restart container to apply changes"
else
    mkdir -p /dev/net
    [[ -c /dev/net/tun ]] || mknod -m 0666 /dev/net/tun c 10 200
    [[ -e $conf ]] || { echo "ERROR: VPN not configured!"; sleep 120; exit 1; }
    [[ -e $cert ]] || grep -Eq '^ *(<ca>|ca +)' "$conf" || { echo "ERROR: VPN CA cert missing!"; sleep 120; exit 1; }

    set -x
    exec sg vpn -c "/usr/sbin/openvpn --cd $dir --config $conf $ext_args ${OTHER_ARGS:-} ${MSS:+--fragment $MSS --mssfix}"
fi
