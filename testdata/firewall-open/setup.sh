#!/bin/bash
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
ufw allow 80/tcp
