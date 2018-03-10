#!/bin/bash
var=$(cat /var/log/snort/alert | tail -n 1 | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
iptables -A INPUT -s $var -j DROP
echo "Subject: SYN Flood Detected" | sendmail bikram@localhost
