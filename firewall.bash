#!/usr/bin/env bash
#
# firewall.bash
# dustin.decker@1on1security.com

# This is a LOCAL linux iptables firewall configuration, intended for use in conjunction with additional
# security controls such as Network Security Groups and/or ACLs.
#
# Requirements: ipset must be installed.
# ubuntu 20.04, example: sudo apt install ipset

# RESET iptables
iptables -F # Flush all existing rules in the chains
iptables -X # delete all user-defined chains

# Create a "Tor" chain.
iptables -N tor
iptables -A tor -j LOG --log-prefix "Firewall Tor Dropped "
iptables -A tor -j DROP

# Create a "Talos" chain.
iptables -N talos
iptables -A talos -j LOG --log-prefix "Firewall Talos Dropped "
iptables -A talos -j DROP

# Create a "Emerging Threats" chain.
iptables -N emerging
iptables -A emerging -j LOG --log-prefix "Firewall ET Dropped "
iptables -A emerging -j DROP

# Create a "Dshield" chain.
iptables -N dshield
iptables -A dshield -j LOG --log-prefix "Firewall Dshield Dropped "
iptables -A dshield -j DROP

# Create a "Catch All" chain.
iptables -N catch
iptables -A catch -j LOG --log-prefix "Firewall Catch Dropped "
iptables -A catch -j DROP

# Set the default policy for each chain to ACCEPT
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

# destroy ipsets for threats and starlink-denver, if present.
ipset destroy tor > /dev/null 2>&1
ipset destroy talos > /dev/null 2>&1
ipset destroy emerging > /dev/null 2>&1
ipset destroy dshield > /dev/null 2>&1
ipset destroy my-allow-list > /dev/null 2>&1

# create ipsets for threats and starlink-denver.
ipset create tor hash:net hashsize 4096
ipset create talos hash:net hashsize 4096
ipset create emerging hash:net hashsize 4096
ipset create dshield hash:net hashsize 4096
ipset create my-allow-list hash:net hashsize 4096

# fetch tor exit node list into threats ipset.
curl -sSL "https://check.torproject.org/torbulkexitlist" | sed '/^#/d' | while read IP; do
        ipset -q -A tor $IP
done

# fetch emerging-threats list into threats ipset.
curl -sSL "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt" |  sed '/^#/d' | while read IP; do
        ipset -q -A emerging $IP
done

# fetch emerging-threats list into threats ipset.
curl -sSL "https://opendbl.net/lists/talos.list" |  sed '/^#/d' | while read IP; do
        ipset -q -A talos $IP
done

# Fetch dshield.org list into threats ipset
curl -sSL "https://feeds.dshield.org/block.txt" | sed '/^#/d' | cut -f 1-3 | while read start_ip end_ip prefix_len; do
        ip_range="$start_ip/$prefix_len"
        ipset -q -A dshield $ip_range
done

# fetch starlink-denver list into my-allow-list ipset.
#curl -sSL "https:// fetch my personal allow list" | while read IP; do
#        ipset -q -A my-allow-list $IP
#done

# DROP any inbound connection from threat lists.
iptables -A INPUT -m set --match-set tor src -j tor
iptables -A INPUT -m set --match-set emerging src -j emerging
iptables -A INPUT -m set --match-set talos src -j talos
iptables -A INPUT -m set --match-set dshield src -j dshield

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopbacks such as DNS queries
iptables -A INPUT -s 127.0.0.1 -d 127.0.0.53 -j ACCEPT
iptables -A INPUT -s 127.0.0.53 -d 127.0.0.1 -j ACCEPT
iptables -A INPUT -s 1.1.1.1 -d 10.0.0.10 -j ACCEPT
iptables -A INPUT -s 10.0.0.10 -d 1.1.1.1 -j ACCEPT
iptables -A INPUT -s 8.8.8.8 -d 10.0.0.10 -j ACCEPT
iptables -A INPUT -s 10.0.0.10 -d 8.8.8.8 -j ACCEPT
iptables -A INPUT -s 10.0.0.2 -d 10.0.0.10 -j ACCEPT
iptables -A INPUT -s 10.0.0.10 -d 10.0.0.2 -j ACCEPT

# Allow outbound 80,443
iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -j ACCEPT

# Allow TCP 2222,10000 from my-allow-list
iptables -A INPUT -m set --match-set my-allow-list src -p tcp -m multiport --dports 2222,10000 -j ACCEPT

# Allow web ports from everywhere
iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT

# DROP any packet not explicitly allowed by earlier rules.
iptables -A INPUT -j catch
