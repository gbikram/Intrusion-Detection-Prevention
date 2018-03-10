#!/bin/bash
var=$(cat /var/log/snort/portscan.log | tail -n 4 | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | tail -n 1)
iptables -A INPUT -s $var -j DROP
echo "Subject: Portscan" | sendmail bikram@localhost
