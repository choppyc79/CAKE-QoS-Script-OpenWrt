#!/bin/sh
############################################################

### Interfaces ###
WAN="pppoe-wan"     # Device used for the 'WAN' interface (e.g., eth0, eth1.2, wan, etc.)
LAN="br-lan"        # Define LAN interface

# Traffic shaping method
DOWNSHAPING_METHOD="ctinfo"  # Options: "ctinfo", "lan"

echo "Setting up cake.qos..."

############################################################

### CAKE settings ###
BANDWIDTH_DOWN="800"   # ~80-95% of your download speed in Mbit
BANDWIDTH_UP="100"     # ~80-95% of your upload speed in Mbit

AUTORATE_INGRESS="no"  # "yes" to enable CAKE's automatic ingress rate estimation

OVERHEAD="42"           # Between -64 and 256
MPU="84"                # Between 0 and 256
LINK_COMPENSATION=""    # "atm" | "ptm" | "noatm" or leave blank

# If above values are unset, you can use one of the presets below
COMMON_LINK_PRESETS="raw" 

ETHER_VLAN_KEYWORD=""   # "1" to "3" for 4, 8, or 12 bytes VLAN overhead enter (ether-vlan)

PRIORITY_QUEUE_INGRESS="diffserv4"  # "besteffort" | "diffserv3" | "diffserv4" | "diffserv8"
PRIORITY_QUEUE_EGRESS="diffserv4"

HOST_ISOLATION="no"     # "yes" enables host isolation to prevent bandwidth hogging

NAT_INGRESS="yes"       # Enables NAT fairness on ingress
NAT_EGRESS="yes"        # Enables NAT fairness on egress

WASH_INGRESS="no"       # "yes" clears DSCP marks on ingress
WASH_EGRESS="yes"       # "yes" clears DSCP marks on egress

INGRESS_MODE="no"       # Enables more aggressive dropping to maintain fairness

ACK_FILTER_EGRESS="auto"  # "yes" | "no" | "auto" – only applies to egress

RTT=""  # Optional RTT shaping window in ms (e.g., 40–300)

EXTRA_PARAMETERS_INGRESS="memlimit 32mb"  # Custom cake parameters
EXTRA_PARAMETERS_EGRESS="memlimit 32mb"

############################################################

### Rules settings ###
CHAIN="FORWARD"         # Default chain for nftables rules

DSCP_ICMP="CS0"         # DSCP value for ICMP traffic
DSCP_GAMING="CS4"       # DSCP value for game traffic

# Known rules (optional)
BROADCAST_VIDEO="no"           # YouTube Live, Twitch, Vimeo, etc. to CS3
GAMING="no"                    # Xbox, PS, CoD, FIFA, etc. to CS4
GAME_STREAMING="no"            # NVIDIA GeForce NOW, etc. to AF42
MULTIMEDIA_CONFERENCING="no"   # Zoom, Teams, Skype, etc. to AF41
TELEPHONY="no"                 # VoIP apps like WhatsApp, Discord, etc.


############################################################

### Ports settings ###

## Don't add ports "80", "443", "8080", and "1935" below — rules for them already exist.
## You may delete the sample ports below if not needed.

## Game ports (prioritized automatically if unmarked)
TCP_SRC_GAME_PORTS=""
TCP_DST_GAME_PORTS=""
UDP_SRC_GAME_PORTS=""
UDP_DST_GAME_PORTS=""
                    ## "SRC" = Source port | "DST" = Destination port
                    # Optional: Add specific TCP/UDP ports used by games.
                    # Use commas to separate values or ranges (e.g., 27000-27030).

## Bulk ports
TCP_SRC_BULK_PORTS=""
TCP_DST_BULK_PORTS=""
UDP_SRC_BULK_PORTS=""
UDP_DST_BULK_PORTS=""
                    ## For bulk traffic like BitTorrent.
                    # Set known BitTorrent ports and define them here.
                    # Use commas or port ranges A-B.

## Other ports [OPTIONAL]
DSCP_OTHER_PORTS="CS0"  # DSCP value for 'other' ports.

TCP_SRC_OTHER_PORTS=""
TCP_DST_OTHER_PORTS=""
UDP_SRC_OTHER_PORTS=""
UDP_DST_OTHER_PORTS=""
                    ## Custom port-based DSCP marking.
                    # Define TCP/UDP ports to mark with the DSCP value above.

############################################################

### IP address settings ###

## Define static IPs via OpenWrt UI: Network → DHCP and DNS → Static Leases

## Game consoles (Static IPs)
IPV4_GAME_CONSOLES_STATIC_IP="192.168.1.200-192.168.1.201"
IPV6_GAME_CONSOLES_STATIC_IP="IPv6::200-IPv6::201"
                    # Mark all traffic from these IPs (except for exempt ports) as gaming.
                    # Supports single IP or range (A-B), comma-separated.

## TorrentBox (Static IPs)
IPV4_TORRENTBOX_STATIC_IP=""
IPV6_TORRENTBOX_STATIC_IP=""
                    # Mark all traffic from these IPs as bulk.
                    # Supports IPv4/IPv6 ranges as above.

## Other static IP addresses [OPTIONAL]
DSCP_OTHER_STATIC_IP="CS0"  # DSCP value to use for marking below IPs.
IPV4_OTHER_STATIC_IP=""
IPV6_OTHER_STATIC_IP=""
                    # Mark all traffic from these IPs with the defined DSCP value.
                    # Supports IP ranges, comma-separated.

######################################################################################################################

### Change default OpenWrt settings ###

DEFAULT_QDISC="fq_codel"  # Options: "fq_codel" | "cake"
                          # fq_codel = Good general-purpose scheduler (OpenWrt default)
                          # cake     = Best for WAN shaping, heavier CPU usage

TCP_CONGESTION_CONTROL="cubic"  # Options: "cubic" | "bbr"
                              # bbr = Google's congestion algorithm (used on YouTube)
                              # cubic = Default on most Linux systems

ECN="2"  # Explicit Congestion Notification: 0=disable, 1=initiate/accept, 2=accept only
         # See: https://www.bufferbloat.net/projects/cerowrt/wiki/Enable_ECN/

######################################################################################################################


#########################      #########################      #########################      #########################
### DO NOT EDIT BELOW ###      ### DO NOT EDIT BELOW ###      ### DO NOT EDIT BELOW ###      ### DO NOT EDIT BELOW ###
### DO NOT EDIT BELOW ###      ### DO NOT EDIT BELOW ###      ### DO NOT EDIT BELOW ###      ### DO NOT EDIT BELOW ###
#########################      #########################      #########################      #########################

######################################################################################################################

# Required packages
REQUIRED_PACKAGES="tc-full kmod-sched-cake kmod-tcp-bbr kmod-sched-ctinfo kmod-ifb"

# Detect package manager
detect_package_manager() {
    if command -v opkg >/dev/null 2>&1; then
        echo "opkg"
    elif command -v apk >/dev/null 2>&1; then
        echo "apk"
    else
        echo "none"
    fi
}

# Check if package is installed
is_package_installed() {
    case "$1" in
        opkg) opkg list-installed 2>/dev/null | grep -qw "$2" ;;
        apk)  apk info 2>/dev/null | grep -qw "$2" ;;
    esac
}

# Get package manager
PACKAGE_MANAGER=$(detect_package_manager)

if [ "$PACKAGE_MANAGER" = "none" ]; then
    echo "Error: No supported package manager (opkg or apk) found."
    return 1 2>/dev/null || exit 1
fi

# Track if any packages are missing
MISSING=0

for pkg in $REQUIRED_PACKAGES; do
    if ! is_package_installed "$PACKAGE_MANAGER" "$pkg"; then
        MISSING=1
        break
    fi
done

# If missing, update and install
if [ "$MISSING" -eq 1 ]; then
    echo "Missing packages detected. Updating package list..."
    [ "$PACKAGE_MANAGER" = "opkg" ] && opkg update >/dev/null 2>&1
    [ "$PACKAGE_MANAGER" = "apk" ]  && apk update  >/dev/null 2>&1

    for pkg in $REQUIRED_PACKAGES; do
        if ! is_package_installed "$PACKAGE_MANAGER" "$pkg"; then
            echo "Installing $pkg..."
            case "$PACKAGE_MANAGER" in
                opkg) opkg install "$pkg" >/dev/null 2>&1 || echo "Warning: Failed to install $pkg" ;;
                apk)  apk add "$pkg"    >/dev/null 2>&1 || echo "Warning: Failed to install $pkg" ;;
            esac
        else
            echo "$pkg already installed. Skipping."
        fi
    done
else
    echo "All required packages are already installed. Skipping installation."
fi

# Continue with the rest of your setup below here
echo "Continuing with the rest of setup..."


clean_ifb_and_ingress() {
    IFB="ifb-$WAN"

    # Delete root qdisc on IFB device (this removes cake on ifb)
    tc qdisc del dev "$IFB" root >/dev/null 2>&1

    # Delete ingress qdisc on WAN device
    tc qdisc del dev "$WAN" ingress >/dev/null 2>&1

    # Delete the IFB interface if it exists
    ip link show "$IFB" >/dev/null 2>&1 && ip link del "$IFB"
	
	# Final forced removal of stubborn IFB qdisc
    ip link set ifb-pppoe-wan down 2>/dev/null
    tc qdisc del dev ifb-pppoe-wan root 2>/dev/null
}

clean_wan() {
    tc qdisc del dev "$WAN" root >/dev/null 2>&1
    tc qdisc del dev "$WAN" ingress >/dev/null 2>&1
}

clean_lan() {
    tc qdisc del dev "$LAN" root >/dev/null 2>&1
    tc qdisc del dev "$LAN" ingress >/dev/null 2>&1
    tc qdisc del dev br-lan root >/dev/null 2>&1
    tc qdisc del dev br-lan ingress >/dev/null 2>&1
}

############################################################

echo "Selected downshaping method: $DOWNSHAPING_METHOD"

case "$DOWNSHAPING_METHOD" in
    ctinfo)
        echo "Using ctinfo method..."
        sleep 1

        # Clean WAN and IFB related qdiscs/interfaces before setup
        clean_ifb_and_ingress
        clean_wan

        # Add ingress qdisc on WAN
        tc qdisc add dev "$WAN" handle ffff: ingress

        # Create and bring up IFB interface
        ip link add name "ifb-$WAN" type ifb
        ip link set "ifb-$WAN" up

        # Redirect DSCP 63 traffic from WAN ingress to IFB
        tc filter add dev "$WAN" parent ffff: protocol all matchall \
            action ctinfo dscp 63 128 \
            mirred egress redirect dev "ifb-$WAN"
        ;;

    lan|"")
        echo "Using LAN method..."
        sleep 1

        # Clean LAN and WAN qdiscs
        clean_ifb_and_ingress
        clean_wan
        clean_lan

        echo "LAN method selected, $LAN configuration applied."
        ;;

    *)
        echo "Invalid downshaping method: $DOWNSHAPING_METHOD. Falling back to LAN."
        DOWNSHAPING_METHOD="lan"
        sleep 1

        clean_ifb_and_ingress
        clean_wan
        clean_lan

        echo "LAN method selected, $LAN configuration applied."
        ;;
esac


############################################################

### Change default OpenWrt settings ###

## Validate and set defaults
case "$DEFAULT_QDISC" in
    fq|fq_codel|cake) ;;  # valid values, no change
    *) DEFAULT_QDISC="fq_codel" ;;
esac

case "$TCP_CONGESTION_CONTROL" in
    reno|cubic|bbr|hybla|scalable) ;;  # valid values
    *) TCP_CONGESTION_CONTROL="cubic" ;;
esac

case "$ECN" in
    0|1|2) ;;  # valid values
    *) ECN="2" ;;
esac

## Add or update sysctl.conf entries with idempotency
set_sysctl_conf() {
    local key="$1"
    local val="$2"
    if grep -q "^$key=" /etc/sysctl.conf; then
        sed -i "s|^$key=.*|$key=$val|" /etc/sysctl.conf
    else
        # Add after first comment line or at end if none
        sed -i "/^#/a $key=$val" /etc/sysctl.conf || echo "$key=$val" >> /etc/sysctl.conf
    fi
}

set_sysctl_conf net.core.default_qdisc "$DEFAULT_QDISC"
set_sysctl_conf net.ipv4.tcp_congestion_control "$TCP_CONGESTION_CONTROL"
set_sysctl_conf net.ipv4.tcp_ecn "$ECN"

## Reload sysctl settings if not already applied
reload_sysctl_if_needed() {
    local key="$1"
    local expected="$2"
    local current
    current=$(sysctl -n "$key")
    [ "$current" != "$expected" ] && sysctl -w "$key=$expected" >/dev/null
}

reload_sysctl_if_needed net.core.default_qdisc "$DEFAULT_QDISC"
reload_sysctl_if_needed net.ipv4.tcp_congestion_control "$TCP_CONGESTION_CONTROL"
reload_sysctl_if_needed net.ipv4.tcp_ecn "$ECN"

############################################################


### CAKE settings ###

## SHAPER parameters
case $BANDWIDTH_DOWN in
    "") BANDWIDTH_DOWN_CAKE="" ;;
    *) BANDWIDTH_DOWN_CAKE="bandwidth ${BANDWIDTH_DOWN}mbit" ;;
esac
case $BANDWIDTH_UP in
    "") BANDWIDTH_UP_CAKE="" ;;
    *) BANDWIDTH_UP_CAKE="bandwidth ${BANDWIDTH_UP}mbit" ;;
esac
if [ "$AUTORATE_INGRESS" = "yes" ] && [ "$BANDWIDTH_DOWN" != "0" ] && [ "$BANDWIDTH_DOWN" != "" ]; then
    AUTORATE_INGRESS_CAKE="autorate-ingress"
fi

## OVERHEAD, MPU and LINK COMPENSATION parameters
case $OVERHEAD in
    "") OVERHEAD="" ;;
    *) OVERHEAD="overhead $OVERHEAD" ;;
esac
case $MPU in
    "") MPU="" ;;
    *) MPU="mpu $MPU" ;;
esac
case $LINK_COMPENSATION in
    atm) LINK_COMPENSATION="atm" ;;
    ptm) LINK_COMPENSATION="ptm" ;;
    noatm) LINK_COMPENSATION="noatm" ;;
    *) LINK_COMPENSATION="" ;;
esac

## COMMON LINK PRESETS keywords
case $COMMON_LINK_PRESETS in
    raw) COMMON_LINK_PRESETS="raw" ;;
    conservative) COMMON_LINK_PRESETS="conservative" ;;
    ethernet) COMMON_LINK_PRESETS="ethernet" ;;
    docsis) COMMON_LINK_PRESETS="docsis" ;;
    pppoe-ptm) COMMON_LINK_PRESETS="pppoe-ptm" ;;
    bridged-ptm) COMMON_LINK_PRESETS="bridged-ptm" ;;
    pppoa-vcmux) COMMON_LINK_PRESETS="pppoa-vcmux" ;;
    pppoa-llc) COMMON_LINK_PRESETS="pppoa-llc" ;;
    pppoe-vcmux) COMMON_LINK_PRESETS="pppoe-vcmux" ;;
    pppoe-llcsnap) COMMON_LINK_PRESETS="pppoe-llcsnap" ;;
    bridged-vcmux) COMMON_LINK_PRESETS="bridged-vcmux" ;;
    bridged-llcsnap) COMMON_LINK_PRESETS="bridged-llcsnap" ;;
    ipoa-vcmux) COMMON_LINK_PRESETS="ipoa-vcmux" ;;
    ipoa-llcsnap) COMMON_LINK_PRESETS="ipoa-llcsnap" ;;
    *) COMMON_LINK_PRESETS="" ;;
esac
case $ETHER_VLAN_KEYWORD in
    1) ETHER_VLAN_KEYWORD="ether-vlan" ;;
    2) ETHER_VLAN_KEYWORD="ether-vlan ether-vlan" ;;
    3) ETHER_VLAN_KEYWORD="ether-vlan ether-vlan ether-vlan" ;;
    *) ETHER_VLAN_KEYWORD="" ;;
esac

## PRIORITY QUEUE parameters
case $PRIORITY_QUEUE_INGRESS in
    besteffort) PRIORITY_QUEUE_INGRESS="besteffort" ;;
    diffserv3) PRIORITY_QUEUE_INGRESS="diffserv3" ;;
    diffserv4) PRIORITY_QUEUE_INGRESS="diffserv4" ;;
    diffserv8) PRIORITY_QUEUE_INGRESS="diffserv8" ;;
    *) PRIORITY_QUEUE_INGRESS="" ;;
esac
case $PRIORITY_QUEUE_EGRESS in
    besteffort) PRIORITY_QUEUE_EGRESS="besteffort" ;;
    diffserv3) PRIORITY_QUEUE_EGRESS="diffserv3" ;;
    diffserv4) PRIORITY_QUEUE_EGRESS="diffserv4" ;;
    diffserv8) PRIORITY_QUEUE_EGRESS="diffserv8" ;;
    *) PRIORITY_QUEUE_EGRESS="" ;;
esac

## HOST ISOLATION parameters
if [ "$HOST_ISOLATION" = "yes" ]; then
    HOST_ISOLATION_INGRESS="dual-dsthost"
    HOST_ISOLATION_EGRESS="dual-srchost"
elif [ "$HOST_ISOLATION" != "yes" ]; then
    HOST_ISOLATION_INGRESS=""
    HOST_ISOLATION_EGRESS=""
fi

## NAT parameters
case $NAT_INGRESS in
    yes) NAT_INGRESS="nat" ;;
    no) NAT_INGRESS="nonat" ;;
    *) NAT_INGRESS="" ;;
esac
case $NAT_EGRESS in
    yes) NAT_EGRESS="nat" ;;
    no) NAT_EGRESS="nonat" ;;
    *) NAT_EGRESS="" ;;
esac

## WASH parameters
case $WASH_INGRESS in
    yes) WASH_INGRESS="wash" ;;
    no) WASH_INGRESS="nowash" ;;
    *) WASH_INGRESS="" ;;
esac
case $WASH_EGRESS in
    yes) WASH_EGRESS="wash" ;;
    no) WASH_EGRESS="nowash" ;;
    *) WASH_EGRESS="" ;;
esac

## INGRESS parameter
case $INGRESS_MODE in
    yes) INGRESS_MODE="ingress" ;;
    *) INGRESS_MODE="" ;;
esac

## ACK-FILTER parameters (AUTO)
# Automatically use the "ack-filter" parameter if your up/down bandwidth is at least 1x15 asymmetric
FORMULA="$(awk "BEGIN { a = $BANDWIDTH_DOWN; b = $BANDWIDTH_UP * 14; print (a > b) }")" > /dev/null 2>&1
if [  "$FORMULA" -eq 1 ]; then
    case $ACK_FILTER_EGRESS in
        yes) ACK_FILTER_EGRESS="yes" ;;
        no) ACK_FILTER_EGRESS="no" ;;
        *) ACK_FILTER_EGRESS="yes" ;;
    esac
fi

## ACK-FILTER parameters
case $ACK_FILTER_EGRESS in
    yes) ACK_FILTER_EGRESS="ack-filter" ;;
    no) ACK_FILTER_EGRESS="no-ack-filter" ;;
    *) ACK_FILTER_EGRESS="" ;;
esac

## RTT parameter
case $RTT in
    "") RTT="" ;;
    *) RTT="rtt ${RTT}ms" ;;
esac

############################################################

### CAKE qdiscs ###

## Determine the ingress device based on method
if [ -n "$BANDWIDTH_DOWN" ]; then
    case "$DOWNSHAPING_METHOD" in
        "ctinfo")
            INGRESS_DEVICE="ifb-$WAN"
            ;;
        *)
            INGRESS_DEVICE="$LAN"
            ;;
    esac

    echo "Ingress device set to: $INGRESS_DEVICE"

    # Delete existing qdisc on the ingress device
    tc qdisc del dev "$INGRESS_DEVICE" root > /dev/null 2>&1

    # Apply CAKE for ingress shaping
    tc qdisc add dev "$INGRESS_DEVICE" root cake \
        $BANDWIDTH_DOWN_CAKE $AUTORATE_INGRESS_CAKE $PRIORITY_QUEUE_INGRESS \
        $HOST_ISOLATION_INGRESS $NAT_INGRESS $WASH_INGRESS $INGRESS_MODE \
        $RTT $COMMON_LINK_PRESETS $ETHER_VLAN_KEYWORD $LINK_COMPENSATION \
        $OVERHEAD $MPU $EXTRA_PARAMETERS_INGRESS
fi

## Outbound / Egress shaping on WAN
if [ -n "$BANDWIDTH_UP" ]; then
    tc qdisc del dev "$WAN" root > /dev/null 2>&1

    tc qdisc add dev "$WAN" root cake \
        $BANDWIDTH_UP_CAKE $PRIORITY_QUEUE_EGRESS $HOST_ISOLATION_EGRESS \
        $NAT_EGRESS $WASH_EGRESS $ACK_FILTER_EGRESS $RTT $COMMON_LINK_PRESETS \
        $ETHER_VLAN_KEYWORD $LINK_COMPENSATION $OVERHEAD $MPU $EXTRA_PARAMETERS_EGRESS
fi

### Init Script ###

## remove old file
rm -f /etc/init.d/cake
cat << "INITSCRIPT" > /etc/init.d/cake
#!/bin/sh /etc/rc.common

USE_PROCD=1

START=99
STOP=99

service_triggers() {
    procd_add_reload_trigger "network"
}

start_service() {
    /etc/init.d/cake enabled || exit 0
    echo start
    /root/cake.sh
}

stop_service() {
    echo stop
    ############################################################

    ### Interface ###
    WAN="$(sed -n '/^WAN=/ { s/WAN="//; s/".*//; p }' /root/cake.sh)"
	LAN="$(sed -n '/^LAN=/ { s/LAN="//; s/".*//; p }' /root/cake.sh)"
	IFB="ifb-$WAN"

    ############################################################

    ## Delete the old qdiscs created by the script
    tc qdisc del dev $WAN root > /dev/null 2>&1
    tc qdisc del dev $WAN ingress > /dev/null 2>&1
	tc qdisc del dev $LAN root > /dev/null 2>&1
	tc qdisc del dev ifb-$WAN root > /dev/null 2>&1

    ## Delete IFB
    ip link del ifb-$WAN 2>/dev/null

    ############################################################

    ## Restore default OpenWrt settings
    sysctl -w net.core.default_qdisc=fq_codel > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_congestion_control=cubic > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_ecn=2 > /dev/null 2>&1

    ############################################################

    ## Flush all rules from the chains
    nft flush chain inet fw4 dscp_marking_ports_ipv4 > /dev/null 2>&1
    nft flush chain inet fw4 dscp_marking_ports_ipv6 > /dev/null 2>&1
    nft flush chain inet fw4 dscp_marking_ip_addresses_ipv4 > /dev/null 2>&1
    nft flush chain inet fw4 dscp_marking_ip_addresses_ipv6 > /dev/null 2>&1

    ## Delete the rule from the chains
    nft delete rule inet fw4 pre_mangle_forward handle "$(nft -a list ruleset | grep "Wash all ISP DSCP marks to CS1 (IPv4)" | sed 's/.* //')" > /dev/null 2>&1
    nft delete rule inet fw4 pre_mangle_forward handle "$(nft -a list ruleset | grep "Wash all ISP DSCP marks to CS1 (IPv6)" | sed 's/.* //')" > /dev/null 2>&1
    nft delete rule inet fw4 pre_mangle_forward handle "$(nft -a list ruleset | grep "DSCP marking rules for ports (IPv4)" | sed 's/.* //')" > /dev/null 2>&1
    nft delete rule inet fw4 pre_mangle_forward handle "$(nft -a list ruleset | grep "DSCP marking rules for ports (IPv6)" | sed 's/.* //')" > /dev/null 2>&1
    nft delete rule inet fw4 pre_mangle_forward handle "$(nft -a list ruleset | grep "DSCP marking rules for IP addresses (IPv4)" | sed 's/.* //')" > /dev/null 2>&1
    nft delete rule inet fw4 pre_mangle_forward handle "$(nft -a list ruleset | grep "DSCP marking rules for IP addresses (IPv6)" | sed 's/.* //')" > /dev/null 2>&1
    nft delete rule inet fw4 pre_mangle_postrouting handle "$(nft -a list ruleset | grep "DSCP marking rules for ports (IPv4)" | sed 's/.* //')" > /dev/null 2>&1
    nft delete rule inet fw4 pre_mangle_postrouting handle "$(nft -a list ruleset | grep "DSCP marking rules for ports (IPv6)" | sed 's/.* //')" > /dev/null 2>&1
    nft delete rule inet fw4 pre_mangle_postrouting handle "$(nft -a list ruleset | grep "DSCP marking rules for IP addresses (IPv4)" | sed 's/.* //')" > /dev/null 2>&1
    nft delete rule inet fw4 pre_mangle_postrouting handle "$(nft -a list ruleset | grep "DSCP marking rules for IP addresses (IPv6)" | sed 's/.* //')" > /dev/null 2>&1

    ## Delete the chains
    nft delete chain inet fw4 pre_mangle_forward > /dev/null 2>&1
    nft delete chain inet fw4 pre_mangle_postrouting > /dev/null 2>&1
    nft delete chain inet fw4 dscp_marking_ports_ipv4 > /dev/null 2>&1
    nft delete chain inet fw4 dscp_marking_ports_ipv6 > /dev/null 2>&1
    nft delete chain inet fw4 dscp_marking_ip_addresses_ipv4 > /dev/null 2>&1
    nft delete chain inet fw4 dscp_marking_ip_addresses_ipv6 > /dev/null 2>&1

    ############################################################
    
    ## Delete nftables files if they exist

    # Check if the file in /tmp exists and delete it
    if [ -f /tmp/00-rules.nft ]; then
        rm /tmp/00-rules.nft
    fi

    # Check if the file in /etc/nftables.d exists and delete it
    if [ -f /etc/nftables.d/00-rules.nft ]; then
        rm /etc/nftables.d/00-rules.nft
    fi
	    
    exit 0
}

restart() {
    echo "Restarting service..."
    /etc/init.d/cake stop
    sleep 1 # Ensure all processes have been properly terminated
    /etc/init.d/cake start    
}

reload_service() {
    restart
}
INITSCRIPT
chmod 755 /etc/init.d/cake > /dev/null 2>&1
/etc/init.d/cake enable > /dev/null 2>&1


############################################################

### Hotplug ###

## remove old file
rm -f /etc/hotplug.d/iface/99-cake
cat << "HOTPLUG" > /etc/hotplug.d/iface/99-cake
#!/bin/sh

[ "$ACTION" = ifup ] || exit 0
[ "$INTERFACE" = wan ] || [ "$INTERFACE" = lan ] || exit 0

# Ensure that the script is executable by Owner
if [ ! -x "/root/cake.sh" ] || [ ! -x "/etc/init.d/cake" ]; then
    chmod 755 /root/cake.sh
    chmod 755 /etc/init.d/cake
fi

# Check if the init script is enabled to reload the script
/etc/init.d/cake enabled || exit 0

# Reloading the script
logger -t cake "Reloading cake.sh due to $ACTION of $INTERFACE ($DEVICE)"
sleep 10 && /etc/init.d/cake restart
HOTPLUG


######################################################################################################################

### Rules settings ###

## Default chain for the rules
case $CHAIN in
    FORWARD) CHAIN="FORWARD" ;;
    POSTROUTING) CHAIN="POSTROUTING" ;;
    *) CHAIN="FORWARD" ;;
esac

## DSCP value for "ICMP" (aka ping)
case $DSCP_ICMP in
    "") DSCP_ICMP="cs0" ;;
    *) DSCP_ICMP="$(printf "%s\n" "$DSCP_ICMP" | awk '{print tolower($0)}')" > /dev/null 2>&1 ;;
esac

## DSCP value for "gaming"
case $DSCP_GAMING in
    "") DSCP_GAMING="cs4" ;;
    *) DSCP_GAMING="$(printf "%s\n" "$DSCP_GAMING" | awk '{print tolower($0)}')" > /dev/null 2>&1 ;;
esac

## DSCP value for "other ports"
case $DSCP_OTHER_PORTS in
    "") DSCP_OTHER_PORTS="cs0" ;;
    *) DSCP_OTHER_PORTS="$(printf "%s\n" "$DSCP_OTHER_PORTS" | awk '{print tolower($0)}')" > /dev/null 2>&1 ;;
esac

## DSCP value for "other static IP addresses"
case $DSCP_OTHER_STATIC_IP in
    "") DSCP_OTHER_STATIC_IP="cs0" ;;
    *) DSCP_OTHER_STATIC_IP="$(printf "%s\n" "$DSCP_OTHER_STATIC_IP" | awk '{print tolower($0)}')" > /dev/null 2>&1 ;;
esac

## Known rules
case $BROADCAST_VIDEO in
    yes) BROADCAST_VIDEO="yes" ;;
    *) BROADCAST_VIDEO="no" ;;
esac
case $GAMING in
    yes) GAMING="yes" ;;
    *) GAMING="no" ;;
esac
case $GAME_STREAMING in
    yes) GAME_STREAMING="yes" ;;
    *) GAME_STREAMING="no" ;;
esac
case $MULTIMEDIA_CONFERENCING in
    yes) MULTIMEDIA_CONFERENCING="yes" ;;
    *) MULTIMEDIA_CONFERENCING="no" ;;
esac
case $TELEPHONY in
    yes) TELEPHONY="yes" ;;
    *) TELEPHONY="no" ;;
esac

## Comments for the rules
DSCP_ICMP_COMMENT="$(printf "%s\n" "$DSCP_ICMP" | awk '{print toupper($0)}')" > /dev/null 2>&1
DSCP_GAMING_COMMENT="$(printf "%s\n" "$DSCP_GAMING" | awk '{print toupper($0)}')" > /dev/null 2>&1
DSCP_OTHER_PORTS_COMMENT="$(printf "%s\n" "$DSCP_OTHER_PORTS" | awk '{print toupper($0)}')" > /dev/null 2>&1
DSCP_OTHER_STATIC_IP_COMMENT="$(printf "%s\n" "$DSCP_OTHER_STATIC_IP" | awk '{print toupper($0)}')" > /dev/null 2>&1

## Automatically add the IPv6 address
IPV6_ADDRESS="$(printf "%.16s\n" "$(uci -q get network.globals.ula_prefix)")" > /dev/null 2>&1
IPV6_GAME_CONSOLES_STATIC_IP="$(printf "%s\n" "$IPV6_GAME_CONSOLES_STATIC_IP" | sed "s/IPv6::/$IPV6_ADDRESS/g")" > /dev/null 2>&1
IPV6_TORRENTBOX_STATIC_IP="$(printf "%s\n" "$IPV6_TORRENTBOX_STATIC_IP" | sed "s/IPv6::/$IPV6_ADDRESS/g")" > /dev/null 2>&1
IPV6_OTHER_STATIC_IP="$(printf "%s\n" "$IPV6_OTHER_STATIC_IP" | sed "s/IPv6::/$IPV6_ADDRESS/g")" > /dev/null 2>&1

## To check if there is a difference between the settings and the rules
if [ "$CHAIN" = "FORWARD" ]; then
    CHECK_CHAIN="$(grep "jump" /etc/nftables.d/00-rules.nft | sed '1q;d' | grep "    " > /dev/null 2>&1 && echo "FORWARD")" > /dev/null 2>&1
elif [ "$CHAIN" != "FORWARD" ]; then
    CHECK_CHAIN="$(grep "jump" /etc/nftables.d/00-rules.nft | sed '1q;d' | grep "#   " > /dev/null 2>&1 && echo "POSTROUTING")" > /dev/null 2>&1
fi
if [ "$BROADCAST_VIDEO" = "yes" ]; then
    CHECK_BROADCAST_VIDEO="$(grep "Live Streaming ports to" /etc/nftables.d/00-rules.nft | grep "    " > /dev/null 2>&1 && echo "yes")" > /dev/null 2>&1
elif [ "$BROADCAST_VIDEO" != "yes" ]; then
    CHECK_BROADCAST_VIDEO="$(grep "Live Streaming ports to" /etc/nftables.d/00-rules.nft | grep "#   " > /dev/null 2>&1 && echo "no")" > /dev/null 2>&1
fi
if [ "$GAMING" = "yes" ]; then
    CHECK_GAMING="$(grep "Known game ports" /etc/nftables.d/00-rules.nft | grep "    " > /dev/null 2>&1 && echo "yes")" > /dev/null 2>&1
elif [ "$GAMING" != "yes" ]; then
    CHECK_GAMING="$(grep "Known game ports" /etc/nftables.d/00-rules.nft | grep "#   " > /dev/null 2>&1 && echo "no")" > /dev/null 2>&1
fi
if [ "$GAME_STREAMING" = "yes" ]; then
    CHECK_GAME_STREAMING="$(grep "Known game streaming" /etc/nftables.d/00-rules.nft | grep "    " > /dev/null 2>&1 && echo "yes")" > /dev/null 2>&1
elif [ "$GAME_STREAMING" != "yes" ]; then
    CHECK_GAME_STREAMING="$(grep "Known game streaming" /etc/nftables.d/00-rules.nft | grep "#   " > /dev/null 2>&1 && echo "no")" > /dev/null 2>&1
fi
if [ "$MULTIMEDIA_CONFERENCING" = "yes" ]; then
    CHECK_MULTIMEDIA_CONFERENCING="$(grep "Known video conferencing ports to" /etc/nftables.d/00-rules.nft | grep "    " > /dev/null 2>&1 && echo "yes")" > /dev/null 2>&1
elif [ "$MULTIMEDIA_CONFERENCING" != "yes" ]; then
    CHECK_MULTIMEDIA_CONFERENCING="$(grep "Known video conferencing ports to" /etc/nftables.d/00-rules.nft | grep "#   " > /dev/null 2>&1 && echo "no")" > /dev/null 2>&1
fi
if [ "$TELEPHONY" = "yes" ]; then
    CHECK_TELEPHONY="$(grep "Known VoIP and VoWiFi ports to" /etc/nftables.d/00-rules.nft | grep "    " > /dev/null 2>&1 && echo "yes")" > /dev/null 2>&1
elif [ "$TELEPHONY" != "yes" ]; then
    CHECK_TELEPHONY="$(grep "Known VoIP and VoWiFi ports to" /etc/nftables.d/00-rules.nft | grep "#   " > /dev/null 2>&1 && echo "no")" > /dev/null 2>&1
fi
CHECK_DSCP_ICMP="$(sed '/ICMP (aka ping) to/!d; s/.*set //; s/ comment.*//' /etc/nftables.d/00-rules.nft)" > /dev/null 2>&1
CHECK_DSCP_GAMING="$(sed '/Game ports to/!d; s/.*set //; s/ comment.*//' /etc/nftables.d/00-rules.nft | sed '1q;d')" > /dev/null 2>&1
CHECK_TCP_SRC_GAME_PORTS="$(sed '/Game ports to/!d; s/.*{ //; s/ }.*//' /etc/nftables.d/00-rules.nft | sed '1q;d')" > /dev/null 2>&1
CHECK_TCP_DST_GAME_PORTS="$(sed '/Game ports to/!d; s/.*{ //; s/ }.*//' /etc/nftables.d/00-rules.nft | sed '2q;d')" > /dev/null 2>&1
CHECK_UDP_SRC_GAME_PORTS="$(sed '/Game ports to/!d; s/.*{ //; s/ }.*//' /etc/nftables.d/00-rules.nft | sed '3q;d')" > /dev/null 2>&1
CHECK_UDP_DST_GAME_PORTS="$(sed '/Game ports to/!d; s/.*{ //; s/ }.*//' /etc/nftables.d/00-rules.nft | sed '4q;d')" > /dev/null 2>&1
CHECK_TCP_SRC_BULK_PORTS="$(sed '/Bulk ports to/!d; s/.*{ //; s/ }.*//' /etc/nftables.d/00-rules.nft | sed '1q;d')" > /dev/null 2>&1
CHECK_TCP_DST_BULK_PORTS="$(sed '/Bulk ports to/!d; s/.*{ //; s/ }.*//' /etc/nftables.d/00-rules.nft | sed '2q;d')" > /dev/null 2>&1
CHECK_UDP_SRC_BULK_PORTS="$(sed '/Bulk ports to/!d; s/.*{ //; s/ }.*//' /etc/nftables.d/00-rules.nft | sed '3q;d')" > /dev/null 2>&1
CHECK_UDP_DST_BULK_PORTS="$(sed '/Bulk ports to/!d; s/.*{ //; s/ }.*//' /etc/nftables.d/00-rules.nft | sed '4q;d')" > /dev/null 2>&1
CHECK_DSCP_OTHER_PORTS="$(sed '/Other ports to/!d; s/.*set //; s/ comment.*//' /etc/nftables.d/00-rules.nft | sed '1q;d')" > /dev/null 2>&1
CHECK_TCP_SRC_OTHER_PORTS="$(sed '/Other ports to/!d; s/.*{ //; s/ }.*//' /etc/nftables.d/00-rules.nft | sed '1q;d')" > /dev/null 2>&1
CHECK_TCP_DST_OTHER_PORTS="$(sed '/Other ports to/!d; s/.*{ //; s/ }.*//' /etc/nftables.d/00-rules.nft | sed '2q;d')" > /dev/null 2>&1
CHECK_UDP_SRC_OTHER_PORTS="$(sed '/Other ports to/!d; s/.*{ //; s/ }.*//' /etc/nftables.d/00-rules.nft | sed '3q;d')" > /dev/null 2>&1
CHECK_UDP_DST_OTHER_PORTS="$(sed '/Other ports to/!d; s/.*{ //; s/ }.*//' /etc/nftables.d/00-rules.nft | sed '4q;d')" > /dev/null 2>&1
CHECK_IPV4_GAME_CONSOLES_STATIC_IP="$(sed '/Game consoles to /!d; s/.*daddr { //; s/ } meta.*//' /etc/nftables.d/00-rules.nft | sed '1q;d')" > /dev/null 2>&1
CHECK_IPV6_GAME_CONSOLES_STATIC_IP="$(sed '/Game consoles to /!d; s/.*daddr { //; s/ } meta.*//' /etc/nftables.d/00-rules.nft | sed '3q;d')" > /dev/null 2>&1
CHECK_IPV4_TORRENTBOX_STATIC_IP="$(sed '/TorrentBox to /!d; s/.*{ //; s/ }.*//' /etc/nftables.d/00-rules.nft | sed '1q;d')" > /dev/null 2>&1
CHECK_IPV6_TORRENTBOX_STATIC_IP="$(sed '/TorrentBox to /!d; s/.*{ //; s/ }.*//' /etc/nftables.d/00-rules.nft | sed '3q;d')" > /dev/null 2>&1
CHECK_DSCP_OTHER_STATIC_IP="$(sed '/Other static IP addresses to/!d; s/.*set //; s/ comment.*//' /etc/nftables.d/00-rules.nft | sed '1q;d')" > /dev/null 2>&1
CHECK_IPV4_OTHER_STATIC_IP="$(sed '/Other static IP addresses to /!d; s/.*{ //; s/ }.*//' /etc/nftables.d/00-rules.nft | sed '1q;d')" > /dev/null 2>&1
CHECK_IPV6_OTHER_STATIC_IP="$(sed '/Other static IP addresses to /!d; s/.*{ //; s/ }.*//' /etc/nftables.d/00-rules.nft | sed '3q;d')" > /dev/null 2>&1


############################################################

### Rules ###

if [ "$CHAIN" != "$CHECK_CHAIN" ] || \
   [ "$DSCP_ICMP" != "$CHECK_DSCP_ICMP" ] || \
   [ "$DSCP_GAMING" != "$CHECK_DSCP_GAMING" ] || \
   [ "$BROADCAST_VIDEO" != "$CHECK_BROADCAST_VIDEO" ] || \
   [ "$GAMING" != "$CHECK_GAMING" ] || \
   [ "$GAME_STREAMING" != "$CHECK_GAME_STREAMING" ] || \
   [ "$MULTIMEDIA_CONFERENCING" != "$CHECK_MULTIMEDIA_CONFERENCING" ] || \
   [ "$TELEPHONY" != "$CHECK_TELEPHONY" ] || \
   [ "$TCP_SRC_GAME_PORTS" != "$CHECK_TCP_SRC_GAME_PORTS" ] || \
   [ "$TCP_DST_GAME_PORTS" != "$CHECK_TCP_DST_GAME_PORTS" ] || \
   [ "$UDP_SRC_GAME_PORTS" != "$CHECK_UDP_SRC_GAME_PORTS" ] || \
   [ "$UDP_DST_GAME_PORTS" != "$CHECK_UDP_DST_GAME_PORTS" ] || \
   [ "$TCP_SRC_BULK_PORTS" != "$CHECK_TCP_SRC_BULK_PORTS" ] || \
   [ "$TCP_DST_BULK_PORTS" != "$CHECK_TCP_DST_BULK_PORTS" ] || \
   [ "$UDP_SRC_BULK_PORTS" != "$CHECK_UDP_SRC_BULK_PORTS" ] || \
   [ "$UDP_DST_BULK_PORTS" != "$CHECK_UDP_DST_BULK_PORTS" ] || \
   [ "$DSCP_OTHER_PORTS" != "$CHECK_DSCP_OTHER_PORTS" ] || \
   [ "$TCP_SRC_OTHER_PORTS" != "$CHECK_TCP_SRC_OTHER_PORTS" ] || \
   [ "$TCP_DST_OTHER_PORTS" != "$CHECK_TCP_DST_OTHER_PORTS" ] || \
   [ "$UDP_SRC_OTHER_PORTS" != "$CHECK_UDP_SRC_OTHER_PORTS" ] || \
   [ "$UDP_DST_OTHER_PORTS" != "$CHECK_UDP_DST_OTHER_PORTS" ] || \
   [ "$IPV4_GAME_CONSOLES_STATIC_IP" != "$CHECK_IPV4_GAME_CONSOLES_STATIC_IP" ] || \
   [ "$IPV6_GAME_CONSOLES_STATIC_IP" != "$CHECK_IPV6_GAME_CONSOLES_STATIC_IP" ] || \
   [ "$IPV4_TORRENTBOX_STATIC_IP" != "$CHECK_IPV4_TORRENTBOX_STATIC_IP" ] || \
   [ "$IPV6_TORRENTBOX_STATIC_IP" != "$CHECK_IPV6_TORRENTBOX_STATIC_IP" ] || \
   [ "$DSCP_OTHER_STATIC_IP" != "$CHECK_DSCP_OTHER_STATIC_IP" ] || \
   [ "$IPV4_OTHER_STATIC_IP" != "$CHECK_IPV4_OTHER_STATIC_IP" ] || \
   [ "$IPV6_OTHER_STATIC_IP" != "$CHECK_IPV6_OTHER_STATIC_IP" ]; then

cat << RULES > /tmp/00-rules.nft


### DSCP marking rules ###


chain pre_mangle_forward {
    type filter hook forward priority mangle -1; policy accept;

    ## Wash all ISP DSCP marks from ingress traffic and set these rules as the default for unmarked traffic
    meta nfproto ipv4 counter ip dscp set cs1 comment "Wash all ISP DSCP marks to CS1 (IPv4)"
    meta nfproto ipv6 counter ip6 dscp set cs1 comment "Wash all ISP DSCP marks to CS1 (IPv6)"

    ## Arrange ruleset
    meta nfproto ipv4 jump dscp_marking_ports_ipv4 comment "DSCP marking rules for ports (IPv4)"
    meta nfproto ipv6 jump dscp_marking_ports_ipv6 comment "DSCP marking rules for ports (IPv6)"
    meta nfproto ipv4 jump dscp_marking_ip_addresses_ipv4 comment "DSCP marking rules for IP addresses (IPv4)"
    meta nfproto ipv6 jump dscp_marking_ip_addresses_ipv6 comment "DSCP marking rules for IP addresses (IPv6)"
    ## Store DSCP in conntrack for restoration on ingress
    ct mark set ip dscp or 128 counter
    ct mark set ip6 dscp or 128 counter
}


chain pre_mangle_postrouting {
    type filter hook postrouting priority mangle -1; policy accept;

    ## Arrange ruleset
    meta nfproto ipv4 jump dscp_marking_ports_ipv4 comment "DSCP marking rules for ports (IPv4)"
    meta nfproto ipv6 jump dscp_marking_ports_ipv6 comment "DSCP marking rules for ports (IPv6)"
    meta nfproto ipv4 jump dscp_marking_ip_addresses_ipv4 comment "DSCP marking rules for IP addresses (IPv4)"
    meta nfproto ipv6 jump dscp_marking_ip_addresses_ipv6 comment "DSCP marking rules for IP addresses (IPv6)"
    ## Store DSCP in conntrack for restoration on ingress
    ct mark set ip dscp or 128 counter
    ct mark set ip6 dscp or 128 counter
}

chain dscp_marking_ports_ipv4 {
    ## Port rules (IPv4) ##

	# ICMP (aka ping)
	meta l4proto icmp counter ip dscp set $DSCP_ICMP comment "ICMP (aka ping) to $DSCP_ICMP_COMMENT"

	# IPv4 - SSH, NTP, and DNS (TCP/UDP)
	meta nfproto ipv4 meta l4proto {tcp, udp} th sport {22, 53, 123, 5353} ip dscp set cs2 counter comment "SSH, NTP, and DNS (src) to CS2"
	meta nfproto ipv4 meta l4proto {tcp, udp} th dport {22, 53, 123, 5353} ip dscp set cs2 counter comment "SSH, NTP, and DNS (dst) to CS2"

	# DNS over TLS (DoT) - TCP only
	meta nfproto ipv4 tcp sport 853 ip dscp set af41 counter comment "DNS over TLS (src) to AF41 (TCP)"
	meta nfproto ipv4 tcp dport 853 ip dscp set af41 counter comment "DNS over TLS (dst) to AF41 (TCP)"

    # HTTP/HTTPS and QUIC
    meta nfproto ipv4 meta l4proto { tcp, udp } th sport { 80, 443 } ip dscp set cs0 counter comment "Ingress traffic to CS0 (TCP and UDP)"
    meta nfproto ipv4 meta l4proto { tcp, udp } th dport { 80, 443 } meta length 0-84 counter ip dscp set cs0 comment "Egress smaller packets (like ACKs, SYN) to CS0 (TCP and UDP) - Downloads in general agressively max out this class"
    meta nfproto ipv4 meta l4proto { tcp, udp } th dport { 80, 443 } meta length 84-1256 limit rate 200/second counter ip dscp set af41 comment "Prioritize egress light browsing (text/live chat/code?) and VoIP (these are the fallback ports) to AF41 (TCP and UDP)"
    meta nfproto ipv4 meta l4proto { tcp, udp } th dport { 80, 443 } meta length 84-1256 limit rate over 200/second counter ip dscp set cs0 comment "Deprioritize egress traffic of packet lengths between 84 and 1256 bytes that have more than 200 pps to CS0 (TCP and UDP)"
	meta nfproto ipv4 meta l4proto tcp th sport { 80, 443 } ct bytes > 1073741824 meta mark set 100 ip dscp set cs1 counter comment "Download >1GB: downgrade to CS1"

    # Live Streaming ports for YouTube Live, Twitch, Vimeo and LinkedIn Live
    meta nfproto ipv4 tcp sport { 1935-1936, 2396, 2935 } ip dscp set cs3 counter comment "Live Streaming ports to CS3 (TCP)"
    meta nfproto ipv4 tcp dport { 1935-1936, 2396, 2935 } ip dscp set cs3 counter comment "Live Streaming ports to CS3 (TCP)"

    # Xbox, PlayStation, Call of Duty, FIFA, Minecraft and Supercell Games
    meta nfproto ipv4 tcp sport { 3074, 3478-3480, 3075-3076, 3659, 25565, 9339 } counter ip dscp set $DSCP_GAMING comment "Known game ports and game consoles ports to $DSCP_GAMING_COMMENT (TCP)"
    meta nfproto ipv4 tcp dport { 3074, 3478-3480, 3075-3076, 3659, 25565, 9339 } counter ip dscp set $DSCP_GAMING comment "Known game ports and game consoles ports to $DSCP_GAMING_COMMENT (TCP)"
    meta nfproto ipv4 udp sport { 88, 3074, 3544, 3075-3079, 3658-3659, 19132-19133, 25565, 9339 } counter ip dscp set $DSCP_GAMING comment "Known game ports and game consoles ports to $DSCP_GAMING_COMMENT (UDP)"
    meta nfproto ipv4 udp dport { 88, 3074, 3544, 3075-3079, 3658-3659, 19132-19133, 25565, 9339 } counter ip dscp set $DSCP_GAMING comment "Known game ports and game consoles ports to $DSCP_GAMING_COMMENT (UDP)"

    # NVIDIA GeForce NOW
    meta nfproto ipv4 tcp sport 49006 counter ip dscp set af42 comment "Known game streaming ports to AF42 (TCP)"
    meta nfproto ipv4 tcp dport 49006 counter ip dscp set af42 comment "Known game streaming ports to AF42 (TCP)"
    meta nfproto ipv4 udp sport { 49003-49006 } counter ip dscp set af42 comment "Known game streaming ports to AF42 (UDP)"
    meta nfproto ipv4 udp dport { 49003-49006 } counter ip dscp set af42 comment "Known game streaming ports to AF42 (UDP)"

    # Zoom, Microsoft Teams, Skype, FaceTime, GoToMeeting, Webex Meeting, Jitsi Meet, Google Meet and TeamViewer
    meta nfproto ipv4 tcp sport { 8801-8802, 5004, 5349, 5938 } counter ip dscp set af41 comment "Known video conferencing ports to AF41 (TCP)"
    meta nfproto ipv4 tcp dport { 8801-8802, 5004, 5349, 5938 } counter ip dscp set af41 comment "Known video conferencing ports to AF41 (TCP)"
    meta nfproto ipv4 udp sport { 3478-3497, 8801-8810, 16384-16387, 16393-16402, 1853, 8200, 9000, 10000, 19302-19309, 5938 } counter ip dscp set af41 comment "Known video conferencing ports to AF41 (UDP)"
    meta nfproto ipv4 udp dport { 3478-3497, 8801-8810, 16384-16387, 16393-16402, 1853, 8200, 9000, 10000, 19302-19309, 5938 } counter ip dscp set af41 comment "Known video conferencing ports to AF41 (UDP)"

    # Voice over Internet Protocol (VoIP) and Voice over WiFi or WiFi Calling (VoWiFi)
    meta nfproto ipv4 tcp sport { 5060-5061 } counter ip dscp set ef comment "Known VoIP and VoWiFi ports to EF (TCP)"
    meta nfproto ipv4 tcp dport { 5060-5061 } counter ip dscp set ef comment "Known VoIP and VoWiFi ports to EF (TCP)"
    meta nfproto ipv4 udp sport { 5060-5061, 500, 4500 } counter ip dscp set ef comment "Known VoIP and VoWiFi ports to EF (UDP)"
    meta nfproto ipv4 udp dport { 5060-5061, 500, 4500 } counter ip dscp set ef comment "Known VoIP and VoWiFi ports to EF (UDP)"

    # Packet mark for Usenet, BitTorrent and "custom bulk ports" to be excluded
    meta nfproto ipv4 tcp sport { 119, 563, 6881-7000, 9000, 28221, 30301, 41952, 49160, 51413, $TCP_SRC_BULK_PORTS } ip dscp cs1 counter meta mark set 40 comment "Packet mark for Usenet, BitTorrent and custom bulk ports to be excluded (TCP)"
    meta nfproto ipv4 tcp dport { 119, 563, 6881-7000, 9000, 28221, 30301, 41952, 49160, 51413, $TCP_DST_BULK_PORTS } ip dscp cs1 counter meta mark set 41 comment "Packet mark for Usenet, BitTorrent and custom bulk ports to be excluded (TCP)"
    meta nfproto ipv4 udp sport { 6771, 6881-7000, 28221, 30301, 41952, 49160, 51413, $UDP_SRC_BULK_PORTS } ip dscp cs1 counter meta mark set 42 comment "Packet mark for Usenet, BitTorrent and custom bulk ports to be excluded (UDP)"
    meta nfproto ipv4 udp dport { 6771, 6881-7000, 28221, 30301, 41952, 49160, 51413, $UDP_DST_BULK_PORTS } ip dscp cs1 counter meta mark set 43 comment "Packet mark for Usenet, BitTorrent and custom bulk ports to be excluded (UDP)"

    # Unmarked TCP traffic
    meta nfproto ipv4 tcp sport != { 80, 443, 8080, 1935-1936, 2396, 2935 } tcp dport != { 80, 443, 8080, 1935-1936, 2396, 2935 } meta mark != { 40, 41, 100 } meta length 0-1256 limit rate over 200/second burst 100 packets ip dscp cs1 counter meta mark set 45 comment "Packet mark for unmarked TCP traffic of packet lengths between 0 and 1256 bytes that have more than 200 pps"
    meta nfproto ipv4 meta l4proto tcp numgen random mod 1000 < 5 meta mark 45 counter meta mark set 0 comment "0.5% probability of unmark a packet that go over 200 pps to be prioritized to $DSCP_GAMING_COMMENT (TCP)"
    meta nfproto ipv4 meta l4proto tcp meta length 0-84 ct direction reply meta mark 45 counter ip dscp set af41 comment "Prioritize ingress unmarked traffic of packet lengths between 0 and 84 bytes that have more than 200 pps to AF41 (TCP)"
    meta nfproto ipv4 meta l4proto tcp meta length 0-84 ct direction original meta mark 45 counter ip dscp set cs0 comment "Prioritize egress unmarked traffic of packet lengths between 0 and 84 bytes that have more than 200 pps to CS0 (TCP)"
    meta nfproto ipv4 meta l4proto tcp meta length > 84 meta mark 45 counter ip dscp set af41 comment "Prioritize unmarked traffic of packet lengths between 84 and 1256 bytes that have more than 200 pps to AF41 (TCP)"
    meta nfproto ipv4 tcp sport != { 80, 443, 8080, 1935-1936, 2396, 2935 } tcp dport != { 80, 443, 8080, 1935-1936, 2396, 2935 } meta mark != { 40, 41, 45, 100 } meta length 0-1256 ip dscp cs1 counter ip dscp set $DSCP_GAMING comment "Prioritize unmarked traffic of packet lengths between 0 and 1256 bytes that have less than 200 pps to $DSCP_GAMING_COMMENT (TCP)"

    # Unmarked UDP traffic (Some games also tend to use really tiny packets on upload side (same range as ACKs))
    meta nfproto ipv4 udp sport != { 80, 443 } udp dport != { 80, 443 } meta mark != { 42, 43 } meta length 0-1256 limit rate over 250/second burst 100 packets ip dscp cs1 counter meta mark set 50 comment "Packet mark for unmarked UDP traffic of packet lengths between 0 and 1256 bytes that have more than 250 pps"
    meta nfproto ipv4 meta l4proto udp numgen random mod 1000 < 5 meta mark 50 counter meta mark set 0 comment "0.5% probability of unmark a packet that go over 250 pps to be prioritized to $DSCP_GAMING_COMMENT (UDP)"
    meta nfproto ipv4 meta l4proto udp meta length 0-84 ct direction reply meta mark 50 counter ip dscp set af41 comment "Prioritize ingress unmarked traffic of packet lengths between 0 and 84 bytes that have more than 250 pps to AF41 (UDP)"
    meta nfproto ipv4 meta l4proto udp meta length 0-84 ct direction original meta mark 50 counter ip dscp set cs0 comment "Prioritize egress unmarked traffic of packet lengths between 0 and 84 bytes that have more than 250 pps to CS0 (UDP)"
    meta nfproto ipv4 meta l4proto udp meta length > 84 meta mark 50 counter ip dscp set af41 comment "Prioritize unmarked traffic of packet lengths between 77 and 1256 bytes that have more than 250 pps to AF41 (UDP)"
    meta nfproto ipv4 udp sport != { 80, 443 } udp dport != { 80, 443 } meta mark != { 42, 43, 50 } meta length 0-1256 ip dscp cs1 counter ip dscp set $DSCP_GAMING comment "Prioritize unmarked traffic of packet lengths between 0 and 1256 bytes that have less than 250 pps to $DSCP_GAMING_COMMENT (UDP) - Gaming & VoIP"
	
	

    ## Custom port rules (IPv4) ##

    # Game ports - Used by games
    meta nfproto ipv4 tcp sport { $TCP_SRC_GAME_PORTS } counter ip dscp set $DSCP_GAMING comment "Game ports to $DSCP_GAMING_COMMENT (TCP)"
    meta nfproto ipv4 tcp dport { $TCP_DST_GAME_PORTS } counter ip dscp set $DSCP_GAMING comment "Game ports to $DSCP_GAMING_COMMENT (TCP)"
    meta nfproto ipv4 udp sport { $UDP_SRC_GAME_PORTS } counter ip dscp set $DSCP_GAMING comment "Game ports to $DSCP_GAMING_COMMENT (UDP)"
    meta nfproto ipv4 udp dport { $UDP_DST_GAME_PORTS } counter ip dscp set $DSCP_GAMING comment "Game ports to $DSCP_GAMING_COMMENT (UDP)"

    # Bulk ports - Used for 'bulk traffic' such as "BitTorrent"
    meta nfproto ipv4 tcp sport { $TCP_SRC_BULK_PORTS } counter ip dscp set cs1 comment "Bulk ports to CS1 (TCP)"
    meta nfproto ipv4 tcp dport { $TCP_DST_BULK_PORTS } counter ip dscp set cs1 comment "Bulk ports to CS1 (TCP)"
    meta nfproto ipv4 udp sport { $UDP_SRC_BULK_PORTS } counter ip dscp set cs1 comment "Bulk ports to CS1 (UDP)"
    meta nfproto ipv4 udp dport { $UDP_DST_BULK_PORTS } counter ip dscp set cs1 comment "Bulk ports to CS1 (UDP)"

    # Other ports [OPTIONAL] - Mark wherever you want
    meta nfproto ipv4 tcp sport { $TCP_SRC_OTHER_PORTS } counter ip dscp set $DSCP_OTHER_PORTS comment "Other ports to $DSCP_OTHER_PORTS_COMMENT (TCP)"
    meta nfproto ipv4 tcp dport { $TCP_DST_OTHER_PORTS } counter ip dscp set $DSCP_OTHER_PORTS comment "Other ports to $DSCP_OTHER_PORTS_COMMENT (TCP)"
    meta nfproto ipv4 udp sport { $UDP_SRC_OTHER_PORTS } counter ip dscp set $DSCP_OTHER_PORTS comment "Other ports to $DSCP_OTHER_PORTS_COMMENT (UDP)"
    meta nfproto ipv4 udp dport { $UDP_DST_OTHER_PORTS } counter ip dscp set $DSCP_OTHER_PORTS comment "Other ports to $DSCP_OTHER_PORTS_COMMENT (UDP)"

}


chain dscp_marking_ports_ipv6 {

    ## Port rules (IPv6) ##

	# ICMPv6 (aka ping)
	meta l4proto ipv6-icmp counter ip6 dscp set $DSCP_ICMP comment "ICMPv6 (aka ping) to $DSCP_ICMP_COMMENT"

	# IPv6 - SSH, NTP, and DNS (TCP/UDP)
	meta nfproto ipv6 meta l4proto {tcp, udp} th sport {22, 53, 123, 5353} ip6 dscp set cs2 counter comment "SSH, NTP, and DNS (src) to CS2"
	meta nfproto ipv6 meta l4proto {tcp, udp} th dport {22, 53, 123, 5353} ip6 dscp set cs2 counter comment "SSH, NTP, and DNS (dst) to CS2"

	# DNS over TLS (DoT) - TCP only
	meta nfproto ipv6 tcp sport 853 ip6 dscp set af41 counter comment "DNS over TLS (src) to AF41 (TCP)"
	meta nfproto ipv6 tcp dport 853 ip6 dscp set af41 counter comment "DNS over TLS (dst) to AF41 (TCP)"

    # HTTP/HTTPS and QUIC
    meta nfproto ipv6 meta l4proto { tcp, udp } th sport { 80, 443 } counter ip6 dscp set cs0 comment "Ingress traffic to CS0 (TCP and UDP)"
    meta nfproto ipv6 meta l4proto { tcp, udp } th dport { 80, 443 } meta length 0-84 counter ip6 dscp set cs0 comment "Egress smaller packets (like ACKs, SYN) to CS0 (TCP and UDP) - Downloads in general agressively max out this class"
    meta nfproto ipv6 meta l4proto { tcp, udp } th dport { 80, 443 } meta length 84-1256 limit rate 200/second counter ip6 dscp set af41 comment "Prioritize egress light browsing (text/live chat/code?) and VoIP (these are the fallback ports) to AF41 (TCP and UDP)"
    meta nfproto ipv6 meta l4proto { tcp, udp } th dport { 80, 443 } meta length 84-1256 limit rate over 200/second counter ip6 dscp set cs0 comment "Deprioritize egress traffic of packet lengths between 84 and 1256 bytes that have more than 200 pps to CS0 (TCP and UDP)"
	meta nfproto ipv6 meta l4proto tcp th sport { 80, 443 } ct bytes > 1073741824 meta mark set 110 ip6 dscp set cs1 counter comment "Download >1GB: downgrade to CS1"

    # Live Streaming ports for YouTube Live, Twitch, Vimeo and LinkedIn Live
    meta nfproto ipv6 tcp sport { 1935-1936, 2396, 2935 } counter ip6 dscp set cs3 comment "Live Streaming ports to CS3 (TCP)"
    meta nfproto ipv6 tcp dport { 1935-1936, 2396, 2935 } counter ip6 dscp set cs3 comment "Live Streaming ports to CS3 (TCP)"

    # Xbox, PlayStation, Call of Duty, FIFA, Minecraft and Supercell Games
    meta nfproto ipv6 tcp sport { 3074, 3478-3480, 3075-3076, 3659, 25565, 9339 } counter ip6 dscp set $DSCP_GAMING comment "Known game ports and game consoles ports to $DSCP_GAMING_COMMENT (TCP)"
    meta nfproto ipv6 tcp dport { 3074, 3478-3480, 3075-3076, 3659, 25565, 9339 } counter ip6 dscp set $DSCP_GAMING comment "Known game ports and game consoles ports to $DSCP_GAMING_COMMENT (TCP)"
    meta nfproto ipv6 udp sport { 88, 3074, 3544, 3075-3079, 3658-3659, 19132-19133, 25565, 9339 } counter ip6 dscp set $DSCP_GAMING comment "Known game ports and game consoles ports to $DSCP_GAMING_COMMENT (UDP)"
    meta nfproto ipv6 udp dport { 88, 3074, 3544, 3075-3079, 3658-3659, 19132-19133, 25565, 9339 } counter ip6 dscp set $DSCP_GAMING comment "Known game ports and game consoles ports to $DSCP_GAMING_COMMENT (UDP)"

    # NVIDIA GeForce NOW
    meta nfproto ipv6 tcp sport 49006 counter ip6 dscp set af42 comment "Known game streaming ports to AF42 (TCP)"
    meta nfproto ipv6 tcp dport 49006 counter ip6 dscp set af42 comment "Known game streaming ports to AF42 (TCP)"
    meta nfproto ipv6 udp sport { 49003-49006 } counter ip6 dscp set af42 comment "Known game streaming ports to AF42 (UDP)"
    meta nfproto ipv6 udp dport { 49003-49006 } counter ip6 dscp set af42 comment "Known game streaming ports to AF42 (UDP)"

    # Zoom, Microsoft Teams, Skype, FaceTime, GoToMeeting, Webex Meeting, Jitsi Meet, Google Meet and TeamViewer
    meta nfproto ipv6 tcp sport { 8801-8802, 5004, 5349, 5938 } counter ip6 dscp set af41 comment "Known video conferencing ports to AF41 (TCP)"
    meta nfproto ipv6 tcp dport { 8801-8802, 5004, 5349, 5938 } counter ip6 dscp set af41 comment "Known video conferencing ports to AF41 (TCP)"
    meta nfproto ipv6 udp sport { 3478-3497, 8801-8810, 16384-16387, 16393-16402, 1853, 8200, 9000, 10000, 19302-19309, 5938 } counter ip6 dscp set af41 comment "Known video conferencing ports to AF41 (UDP)"
    meta nfproto ipv6 udp dport { 3478-3497, 8801-8810, 16384-16387, 16393-16402, 1853, 8200, 9000, 10000, 19302-19309, 5938 } counter ip6 dscp set af41 comment "Known video conferencing ports to AF41 (UDP)"

    # Voice over Internet Protocol (VoIP) and Voice over WiFi or WiFi Calling (VoWiFi)
    meta nfproto ipv6 tcp sport { 5060-5061 } counter ip6 dscp set ef comment "Known VoIP and VoWiFi ports to EF (TCP)"
    meta nfproto ipv6 tcp dport { 5060-5061 } counter ip6 dscp set ef comment "Known VoIP and VoWiFi ports to EF (TCP)"
    meta nfproto ipv6 udp sport { 5060-5061, 500, 4500 } counter ip6 dscp set ef comment "Known VoIP and VoWiFi ports to EF (UDP)"
    meta nfproto ipv6 udp dport { 5060-5061, 500, 4500 } counter ip6 dscp set ef comment "Known VoIP and VoWiFi ports to EF (UDP)"

    # Packet mark for Usenet, BitTorrent and "custom bulk ports" to be excluded
    meta nfproto ipv6 tcp sport { 119, 563, 6881-7000, 9000, 28221, 30301, 41952, 49160, 51413, $TCP_SRC_BULK_PORTS } ip6 dscp cs1 counter meta mark set 70 comment "Packet mark for Usenet, BitTorrent and custom bulk ports to be excluded (TCP)"
    meta nfproto ipv6 tcp dport { 119, 563, 6881-7000, 9000, 28221, 30301, 41952, 49160, 51413, $TCP_DST_BULK_PORTS } ip6 dscp cs1 counter meta mark set 71 comment "Packet mark for Usenet, BitTorrent and custom bulk ports to be excluded (TCP)"
    meta nfproto ipv6 udp sport { 6771, 6881-7000, 28221, 30301, 41952, 49160, 51413, $UDP_SRC_BULK_PORTS } ip6 dscp cs1 counter meta mark set 72 comment "Packet mark for Usenet, BitTorrent and custom bulk ports to be excluded (UDP)"
    meta nfproto ipv6 udp dport { 6771, 6881-7000, 28221, 30301, 41952, 49160, 51413, $UDP_DST_BULK_PORTS } ip6 dscp cs1 counter meta mark set 73 comment "Packet mark for Usenet, BitTorrent and custom bulk ports to be excluded (UDP)"

    # Unmarked TCP traffic
    meta nfproto ipv6 tcp sport != { 80, 443, 8080, 1935-1936, 2396, 2935 } tcp dport != { 80, 443, 8080, 1935-1936, 2396, 2935 } meta mark != { 70, 71, 110 } meta length 0-1256 limit rate over 200/second burst 100 packets ip6 dscp cs1 counter meta mark set 75 comment "Packet mark for unmarked TCP traffic of packet lengths between 0 and 1256 bytes that have more than 200 pps"
    meta nfproto ipv6 meta l4proto tcp numgen random mod 1000 < 5 meta mark 75 counter meta mark set 0 comment "0.5% probability of unmark a packet that go over 200 pps to be prioritized to $DSCP_GAMING_COMMENT (TCP)"
    meta nfproto ipv6 meta l4proto tcp meta length 0-84 ct direction reply meta mark 75 counter ip6 dscp set af41 comment "Prioritize ingress unmarked traffic of packet lengths between 0 and 84 bytes that have more than 200 pps to AF41 (TCP)"
    meta nfproto ipv6 meta l4proto tcp meta length 0-84 ct direction original meta mark 75 counter ip6 dscp set cs0 comment "Prioritize egress unmarked traffic of packet lengths between 0 and 84 bytes that have more than 200 pps to CS0 (TCP)"
    meta nfproto ipv6 meta l4proto tcp meta length > 84 meta mark 75 counter ip6 dscp set af41 comment "Prioritize unmarked traffic of packet lengths between 77 and 1256 bytes that have more than 200 pps to AF41 (TCP)"
    meta nfproto ipv6 tcp sport != { 80, 443, 8080, 1935-1936, 2396, 2935 } tcp dport != { 80, 443, 8080, 1935-1936, 2396, 2935 } meta mark != { 70, 71, 75, 110 } meta length 0-1256 ip6 dscp cs1 counter ip6 dscp set $DSCP_GAMING comment "Prioritize unmarked traffic of packet lengths between 0 and 1256 bytes that have less than 200 pps to $DSCP_GAMING_COMMENT (TCP)"

    # Unmarked UDP traffic (Some games also tend to use really tiny packets on upload side (same range as ACKs))
    meta nfproto ipv6 udp sport != { 80, 443 } udp dport != { 80, 443 } meta mark != { 72, 73 } meta length 0-1256 limit rate over 250/second burst 100 packets ip6 dscp cs1 counter meta mark set 80 comment "Packet mark for unmarked UDP traffic of packet lengths between 0 and 1256 bytes that have more than 250 pps"
    meta nfproto ipv6 meta l4proto udp numgen random mod 1000 < 5 meta mark 80 counter meta mark set 0 comment "0.5% probability of unmark a packet that go over 250 pps to be prioritized to $DSCP_GAMING_COMMENT (UDP)"
    meta nfproto ipv6 meta l4proto udp meta length 0-84 ct direction reply meta mark 80 counter ip6 dscp set af41 comment "Prioritize ingress unmarked traffic of packet lengths between 0 and 84 bytes that have more than 250 pps to AF41 (UDP)"
    meta nfproto ipv6 meta l4proto udp meta length 0-84 ct direction original meta mark 80 counter ip6 dscp set cs0 comment "Prioritize egress unmarked traffic of packet lengths between 0 and 84 bytes that have more than 250 pps to CS0 (UDP)"
    meta nfproto ipv6 meta l4proto udp meta length > 84 meta mark 80 counter ip6 dscp set af41 comment "Prioritize unmarked traffic of packet lengths between 84 and 1256 bytes that have more than 250 pps to AF41 (UDP)"
    meta nfproto ipv6 udp sport != { 80, 443 } udp dport != { 80, 443 } meta mark != { 72, 73, 80 } meta length 0-1256 ip6 dscp cs1 counter ip6 dscp set $DSCP_GAMING comment "Prioritize unmarked traffic of packet lengths between 0 and 1256 bytes that have less than 250 pps to $DSCP_GAMING_COMMENT (UDP) - Gaming & VoIP"
	

    ## Custom port rules (IPv6) ##

    # Game ports - Used by games
    meta nfproto ipv6 tcp sport { $TCP_SRC_GAME_PORTS } counter ip6 dscp set $DSCP_GAMING comment "Game ports to $DSCP_GAMING_COMMENT (TCP)"
    meta nfproto ipv6 tcp dport { $TCP_DST_GAME_PORTS } counter ip6 dscp set $DSCP_GAMING comment "Game ports to $DSCP_GAMING_COMMENT (TCP)"
    meta nfproto ipv6 udp sport { $UDP_SRC_GAME_PORTS } counter ip6 dscp set $DSCP_GAMING comment "Game ports to $DSCP_GAMING_COMMENT (UDP)"
    meta nfproto ipv6 udp dport { $UDP_DST_GAME_PORTS } counter ip6 dscp set $DSCP_GAMING comment "Game ports to $DSCP_GAMING_COMMENT (UDP)"

    # Bulk ports - Used for 'bulk traffic' such as "BitTorrent"
    meta nfproto ipv6 tcp sport { $TCP_SRC_BULK_PORTS } counter ip6 dscp set cs1 comment "Bulk ports to CS1 (TCP)"
    meta nfproto ipv6 tcp dport { $TCP_DST_BULK_PORTS } counter ip6 dscp set cs1 comment "Bulk ports to CS1 (TCP)"
    meta nfproto ipv6 udp sport { $UDP_SRC_BULK_PORTS } counter ip6 dscp set cs1 comment "Bulk ports to CS1 (UDP)"
    meta nfproto ipv6 udp dport { $UDP_DST_BULK_PORTS } counter ip6 dscp set cs1 comment "Bulk ports to CS1 (UDP)"

    # Other ports [OPTIONAL] - Mark wherever you want
    meta nfproto ipv6 tcp sport { $TCP_SRC_OTHER_PORTS } counter ip6 dscp set $DSCP_OTHER_PORTS comment "Other ports to $DSCP_OTHER_PORTS_COMMENT (TCP)"
    meta nfproto ipv6 tcp dport { $TCP_DST_OTHER_PORTS } counter ip6 dscp set $DSCP_OTHER_PORTS comment "Other ports to $DSCP_OTHER_PORTS_COMMENT (TCP)"
    meta nfproto ipv6 udp sport { $UDP_SRC_OTHER_PORTS } counter ip6 dscp set $DSCP_OTHER_PORTS comment "Other ports to $DSCP_OTHER_PORTS_COMMENT (UDP)"
    meta nfproto ipv6 udp dport { $UDP_DST_OTHER_PORTS } counter ip6 dscp set $DSCP_OTHER_PORTS comment "Other ports to $DSCP_OTHER_PORTS_COMMENT (UDP)"

}


chain dscp_marking_ip_addresses_ipv4 {

    ## IP address rules (IPv4) ##

    # Game consoles (Static IP) - Will cover all ports (except ports 80, 443, 8080, Live Streaming and BitTorrent)
    ip daddr { $IPV4_GAME_CONSOLES_STATIC_IP } meta l4proto { tcp, udp } th sport != { 80, 443, 8080, 1935-1936, 2396, 2935 } th dport != { 80, 443, 8080, 1935-1936, 2396, 2935 } meta mark != { 40, 41, 42, 43, 100 } counter ip dscp set $DSCP_GAMING comment "Game consoles to $DSCP_GAMING_COMMENT (TCP and UDP)"
    ip saddr { $IPV4_GAME_CONSOLES_STATIC_IP } meta l4proto { tcp, udp } th sport != { 80, 443, 8080, 1935-1936, 2396, 2935 } th dport != { 80, 443, 8080, 1935-1936, 2396, 2935 } meta mark != { 40, 41, 42, 43, 100 } counter ip dscp set $DSCP_GAMING comment "Game consoles to $DSCP_GAMING_COMMENT (TCP and UDP)"

    # TorrentBox (Static IP) - Mark 'all traffic' as bulk
    ip daddr { $IPV4_TORRENTBOX_STATIC_IP } counter ip dscp set cs1 comment "TorrentBox to CS1"
    ip saddr { $IPV4_TORRENTBOX_STATIC_IP } counter ip dscp set cs1 comment "TorrentBox to CS1"

    # Other static IP addresses [OPTIONAL] - Mark 'all traffic' wherever you want
    ip daddr { $IPV4_OTHER_STATIC_IP } counter ip dscp set $DSCP_OTHER_STATIC_IP comment "Other static IP addresses to $DSCP_OTHER_STATIC_IP_COMMENT"
    ip saddr { $IPV4_OTHER_STATIC_IP } counter ip dscp set $DSCP_OTHER_STATIC_IP comment "Other static IP addresses to $DSCP_OTHER_STATIC_IP_COMMENT"

}


chain dscp_marking_ip_addresses_ipv6 {

    ## IP address rules (IPv6) ##

    # Game consoles (Static IP) - Will cover all ports (except ports 80, 443, 8080, Live Streaming and BitTorrent)
    ip6 daddr { $IPV6_GAME_CONSOLES_STATIC_IP } meta l4proto { tcp, udp } th sport != { 80, 443, 8080, 1935-1936, 2396, 2935 } th dport != { 80, 443, 8080, 1935-1936, 2396, 2935 } meta mark != { 70, 71, 72, 73, 110 } counter ip6 dscp set $DSCP_GAMING comment "Game consoles to $DSCP_GAMING_COMMENT (TCP and UDP)"
    ip6 saddr { $IPV6_GAME_CONSOLES_STATIC_IP } meta l4proto { tcp, udp } th sport != { 80, 443, 8080, 1935-1936, 2396, 2935 } th dport != { 80, 443, 8080, 1935-1936, 2396, 2935 } meta mark != { 70, 71, 72, 73, 110 } counter ip6 dscp set $DSCP_GAMING comment "Game consoles to $DSCP_GAMING_COMMENT (TCP and UDP)"

    # TorrentBox (Static IP) - Mark 'all traffic' as bulk
    ip6 daddr { $IPV6_TORRENTBOX_STATIC_IP } counter ip6 dscp set cs1 comment "TorrentBox to CS1"
    ip6 saddr { $IPV6_TORRENTBOX_STATIC_IP } counter ip6 dscp set cs1 comment "TorrentBox to CS1"

    # Other static IP addresses [OPTIONAL] - Mark 'all traffic' wherever you want
    ip6 daddr { $IPV6_OTHER_STATIC_IP } counter ip6 dscp set $DSCP_OTHER_STATIC_IP comment "Other static IP addresses to $DSCP_OTHER_STATIC_IP_COMMENT"
    ip6 saddr { $IPV6_OTHER_STATIC_IP } counter ip6 dscp set $DSCP_OTHER_STATIC_IP comment "Other static IP addresses to $DSCP_OTHER_STATIC_IP_COMMENT"

}
RULES

	process_ipblock() {
    local VAR="$1"         # env var containing static IP
    local LABEL="$2"       # comment marker to locate block, e.g. "Game consoles to"
    local LINES="$3"       # how many lines to toggle (e.g. 4)
    local ENABLED_PATTERN="    "
    local DISABLED_PATTERN="#   "

    for i in $(seq 0 $((LINES - 1))); do
        local LINENUM=$((i + 1))
        local SEARCH_LINE="$(grep "$LABEL" /tmp/00-rules.nft | sed "${LINENUM}q;d")"

        if [ "$VAR" != "" ]; then
            echo "$SEARCH_LINE" | grep -q "$ENABLED_PATTERN" && continue
            sed -i "/$LABEL/{G;s/\\nX\\{$i\\}//;tend;x;s/^/X/;x};P;d;:end;s/$DISABLED_PATTERN/$ENABLED_PATTERN/;:a;n;ba" /tmp/00-rules.nft
        else
            echo "$SEARCH_LINE" | grep -q "$DISABLED_PATTERN" && continue
            sed -i "/$LABEL/{G;s/\\nX\\{$i\\}//;tend;x;s/^/X/;x};P;d;:end;s/$ENABLED_PATTERN/$DISABLED_PATTERN/;:a;n;ba" /tmp/00-rules.nft
        fi
    done
}

process_portblock() {
    local VAR="$1"       # Environment variable value (checked for non-empty)
    local LABEL="$2"     # Block label to match, e.g. "Game ports to"
    local LINES="$3"     # Total line count for this block
    local IDX_LIST="$4"  # Space-separated line indices to process

    local ENABLED_PATTERN="    "
    local DISABLED_PATTERN="#   "

    for i in $IDX_LIST; do
        local LINENUM=$((i + 1))
        local SEARCH_LINE="$(grep "$LABEL" /tmp/00-rules.nft | sed "${LINENUM}q;d")"

        if [ "$VAR" != "" ]; then
            echo "$SEARCH_LINE" | grep -q "$ENABLED_PATTERN" && continue
            sed -i "/$LABEL/{G;s/\\nX\\{$i\\}//;tend;x;s/^/X/;x};P;d;:end;s/$DISABLED_PATTERN/$ENABLED_PATTERN/;:a;n;ba" /tmp/00-rules.nft
        else
            echo "$SEARCH_LINE" | grep -q "$DISABLED_PATTERN" && continue
            sed -i "/$LABEL/{G;s/\\nX\\{$i\\}//;tend;x;s/^/X/;x};P;d;:end;s/$ENABLED_PATTERN/$DISABLED_PATTERN/;:a;n;ba" /tmp/00-rules.nft
        fi
    done
}

process_knownblock() {
    local VAR="$1"     # e.g. "$GAMING"
    local LABEL="$2"   # e.g. "Known game ports"

    if [ "$VAR" = "yes" ]; then
        grep "$LABEL" /tmp/00-rules.nft | grep "    " > /dev/null 2>&1 || \
            sed -i "/$LABEL/s/#   /    /g" /tmp/00-rules.nft > /dev/null 2>&1
    else
        grep "$LABEL" /tmp/00-rules.nft | grep "#   " > /dev/null 2>&1 || \
            sed -i "/$LABEL/s/    /#   /g" /tmp/00-rules.nft > /dev/null 2>&1
    fi
}

enable_forward_chain() {
    sed -i "14,20 s/#/ /" /tmp/00-rules.nft > /dev/null 2>&1
    sed -i "24 s/c/#c/; 25,34 s/ /#/; 35 s/}/#}/" /tmp/00-rules.nft > /dev/null 2>&1
}

enable_postrouting_chain() {
    sed -i "14,20 s/ /#/" /tmp/00-rules.nft > /dev/null 2>&1
    sed -i "24 s/#c/c/; 25,34 s/#/ /; 35 s/#}/}/" /tmp/00-rules.nft > /dev/null 2>&1
}

    ############################################################

## Default chain for the rules
if [ "$CHAIN" = "FORWARD" ]; then
    grep "jump" /tmp/00-rules.nft | sed '1q;d' | grep "    " > /dev/null 2>&1 || enable_forward_chain
    grep "jump" /tmp/00-rules.nft | sed '5q;d' | grep "#   " > /dev/null 2>&1 || enable_forward_chain
else
    grep "jump" /tmp/00-rules.nft | sed '1q;d' | grep "#   " > /dev/null 2>&1 || enable_postrouting_chain
    grep "jump" /tmp/00-rules.nft | sed '5q;d' | grep "    " > /dev/null 2>&1 || enable_postrouting_chain
fi

    ############################################################

### Known rules ###

process_knownblock "$BROADCAST_VIDEO"         "Live Streaming ports to"
process_knownblock "$GAMING"                  "Known game ports"
process_knownblock "$GAME_STREAMING"          "Known game streaming"
process_knownblock "$MULTIMEDIA_CONFERENCING" "Known video conferencing ports to"
process_knownblock "$TELEPHONY"               "Known VoIP and VoWiFi ports to"

    ############################################################

### Custom port rules ###

# Game Ports
process_portblock "$TCP_SRC_GAME_PORTS" "Game ports to" 8 "0 4"
process_portblock "$TCP_DST_GAME_PORTS" "Game ports to" 8 "1 5"
process_portblock "$UDP_SRC_GAME_PORTS" "Game ports to" 8 "2 6"
process_portblock "$UDP_DST_GAME_PORTS" "Game ports to" 8 "3 7"

# Bulk Ports
process_portblock "$TCP_SRC_BULK_PORTS" "Bulk ports to" 8 "0 4"
process_portblock "$TCP_DST_BULK_PORTS" "Bulk ports to" 8 "1 5"
process_portblock "$UDP_SRC_BULK_PORTS" "Bulk ports to" 8 "2 6"
process_portblock "$UDP_DST_BULK_PORTS" "Bulk ports to" 8 "3 7"

# Other Ports
process_portblock "$TCP_SRC_OTHER_PORTS" "Other ports to" 8 "0 4"
process_portblock "$TCP_DST_OTHER_PORTS" "Other ports to" 8 "1 5"
process_portblock "$UDP_SRC_OTHER_PORTS" "Other ports to" 8 "2 6"
process_portblock "$UDP_DST_OTHER_PORTS" "Other ports to" 8 "3 7"

    ############################################################

### IP address rules ###

# Game Consoles
process_ipblock "$IPV4_GAME_CONSOLES_STATIC_IP" "Game consoles to" 2
process_ipblock "$IPV6_GAME_CONSOLES_STATIC_IP" "Game consoles to" 4

# TorrentBox
process_ipblock "$IPV4_TORRENTBOX_STATIC_IP" "TorrentBox to" 2
process_ipblock "$IPV6_TORRENTBOX_STATIC_IP" "TorrentBox to" 4

# Other static IPs
process_ipblock "$IPV4_OTHER_STATIC_IP" "Other static IP addresses to" 2
process_ipblock "$IPV6_OTHER_STATIC_IP" "Other static IP addresses to" 4


    ############################################################

    ### nft file ###

    ## Copy the already edited *.nft file to the directory "/etc/nftables.d"
    cp "/tmp/00-rules.nft" "/etc/nftables.d/00-rules.nft"

fi

############################################################

### Paths ###
INIT_FILE="/etc/init.d/cake"
HOTPLUG_FILE="/etc/hotplug.d/iface/99-cake"
RULE_TMP="/tmp/00-rules.nft"
RULE_ETC="/etc/nftables.d/00-rules.nft"

### Function to check existence and minimal validity ###
check_file() {
    FILE="$1"
    DESC="$2"

    if [ ! -f "$FILE" ]; then
        echo "✖ Error: $DESC ($FILE) does not exist."
        return 1
    fi

    echo "✔ $DESC ($FILE) exists."

    if grep -q "cake" "$FILE"; then
        echo "✔ $DESC contains expected content."
    else
        echo "⚠ Warning: $DESC does not contain expected content."
    fi
}

echo "### Checking required system files ###"
check_file "$INIT_FILE" "Init script"
check_file "$HOTPLUG_FILE" "Hotplug script"
echo

echo "### Checking nftables rule files ###"
[ -f "$RULE_TMP" ] && echo "✔ $RULE_TMP exists." || echo "✖ $RULE_TMP is missing."
[ -f "$RULE_ETC" ] && echo "✔ $RULE_ETC exists." || echo "✖ $RULE_ETC is missing."
echo

# Abort if /tmp/00-rules.nft is missing
if [ ! -f "$RULE_TMP" ]; then
    echo "✖ Critical: $RULE_TMP is required but missing. Aborting."
    exit 1
fi

echo "All essential files present. Continuing..."


echo "Checking if nftables rules from $RULE_TMP are loaded..."
sleep 1

# Get current nftables ruleset
CURRENT_RULESET=$(nft list ruleset 2>/dev/null)
EXPECTED_RULESET=$(cat "$RULE_TMP")

# Compare normalized versions (remove whitespace)
if echo "$CURRENT_RULESET" | tr -d '[:space:]' | grep -q "$(echo "$EXPECTED_RULESET" | tr -d '[:space:]')"; then
    echo "✔ nftables ruleset matches $RULE_TMP."
else
    echo "✖ Loaded nftables ruleset does not match $RULE_TMP."
    exit 1
fi

sleep 1

# Reload firewall to apply rules
echo "Reloading firewall to apply rules..."
fw4 reload
if [ $? -ne 0 ]; then
    echo "Error: Failed to reload firewall."
    exit 1  # Stop execution if firewall reload fails
fi
echo "Firewall reloaded."
sleep 1

# Show queue disciplines for WAN and LAN/IFB
echo "Displaying queue disciplines..."

# Helper to safely show qdisc and handle errors
show_qdisc() {
    local DEV="$1"
    echo "Queue discipline for $DEV:"
    if ! tc qdisc show dev "$DEV" 2>/dev/null; then
        echo "Error: Failed to show qdisc for $DEV."
        exit 1
    fi
}

show_cake_qdisc() {
    tc qdisc show dev "$1" 2>/dev/null | grep -i 'cake'
}

case "$DOWNSHAPING_METHOD" in
    "ctinfo")
        echo "Downshaping method: ctinfo"
        if ip link show "ifb-$WAN" > /dev/null 2>&1; then
            echo "IFB device for WAN exists. Showing CAKE qdisc for $WAN and ifb-$WAN..."
            show_cake_qdisc "$WAN"
            show_cake_qdisc "ifb-$WAN"
        else
            echo "IFB device for WAN (ifb-$WAN) not found. Showing CAKE qdisc for $WAN only."
            show_cake_qdisc "$WAN"
        fi
        ;;
    "lan" | "")
        echo "Downshaping method: LAN"
        show_cake_qdisc "$WAN"
        show_cake_qdisc "$LAN"
        ;;
    *)
        echo "Invalid downshaping method: $DOWNSHAPING_METHOD. Defaulting to LAN."
        DOWNSHAPING_METHOD="lan"
        echo "Downshaping method: LAN"
        show_cake_qdisc "$WAN"
        show_cake_qdisc "$LAN"
        ;;
esac

sleep 1

# Show detailed qdisc stats
echo "Displaying qdisc statistics..."
tc -s qdisc
if [ $? -ne 0 ]; then
    echo "Error: Failed to display qdisc statistics."
    exit 1  # Stop execution if tc command fails
fi

sleep 1
echo "Cake.qos is now installed and running"


###########################################################
