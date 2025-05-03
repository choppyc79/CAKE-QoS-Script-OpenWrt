# CAKE QoS Script (OpenWrt)

## Quick Overview
1. The script launches the CAKE qdisc (like SQM would do), and **you do not need SQM at all**.
2. Auto installs all required packages and Auto setups Cake-QOS
3. It has rules to prioritize **non-bulk** *unmarked traffic* like **gaming** and **VoIP**, that means you don't need to add **game ports**, but if you want you can also add **game ports** and static IP of **game consoles** to prioritize that traffic (although it is not necessary).
4. It has rules to give high priority to known **Video conferencing**, **VoIP** and **VoWiFi** ports.
5. Easily change the **default OpenWrt settings** like `default qdisc`, `TCP congestion control` and `ECN`.
6. **`irqbalance`** and **`Packet Steering`** options to equally distribute the load of packet processing over all available cores and probably increase performance.
7. It has **`Init Script`** so that from the LuCI web interface (**`System -> Startup`**) you can Enable, Disable, Start, Restart and Stop the script.
8. It has **`Hotplug`** to automatically reload the script.

## Install
Copy and paste this into your SSH client:
```
rm -f /root/cake.sh && rm -f /etc/init.d/cake && rm -f /etc/hotplug.d/iface/99-cake && rm -f /etc/nftables.d/*-rules.nft && wget -O /root/cake.sh https://raw.githubusercontent.com/choppyc79/CAKE-QoS-Script-OpenWrt/main/cake.sh && chmod 755 /root/cake.sh && sh /root/cake.sh

```
The **`cake.sh`** script is located in the **`/root/`** folder on the router and you have to edit this - it will install with the deafult settings, these can be changed below - 
1. Change the **CAKE settings** according to your connection type and also change the other settings (like rules, ports, IP address,  irqbalance, etc.).
2. You can delete the **ports** and **IP address** from the script, because are just examples.
3. Once you've finished editing the script, use this command to run the script:
```
./cake.sh
```

## CLI
Command to run the script:
```
./cake.sh
```

Others important commands:
```
# To check if the DSCP marking is working
tc -s qdisc


# To check your CAKE settings
tc qdisc | grep cake


# To check the nftables rules
nft list ruleset


# To check if changed the default OpenWrt settings
sysctl net.core.default_qdisc
sysctl net.ipv4.tcp_congestion_control
sysctl net.ipv4.tcp_ecn


# To check if irqbalance or packet steering are enabled or disabled
uci show irqbalance.irqbalance.enabled
uci show network.globals.packet_steering
```

## Tip
* Don't use **`Software flow offloading`**, it will break the **rules** and **CAKE**.

## Uninstall/Remove
Copy and paste this into your SSH client:
```
/etc/init.d/cake stop && rm /root/cake.sh && rm /etc/init.d/cake && rm /etc/hotplug.d/iface/99-cake && rm /etc/nftables.d/*-rules.nft && sed -i "/default_qdisc/d; /tcp_congestion_control/d; /tcp_ecn/d" /etc/sysctl.conf && uci set dhcp.odhcpd.loglevel="4" && uci commit && reload_config && /etc/init.d/network restart

```


