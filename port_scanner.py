#!/usr/bin/env python3

from scapy.all import *
import re

try:
    host = input("Enter a host address: ")

    p = list(input("Enter the ports to scan: ").split(","))
    temp = map(int, p)
    ports = list(temp)

    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host):
        print("\nScanning...")
        print("Host:", host)
        print("Ports:", ports)

        for port in ports:
            ans, unans = sr(
                IP(dst=host)/TCP(dport=port, flags="S"),
                verbose=0,
                timeout=2
            )

            for s, r in ans:
                if r.haslayer(TCP) and r[TCP].flags == 0x12:
                    print("[+] {} Open".format(port))
                    send(IP(dst=host)/TCP(dport=port, flags="R"), verbose=0)

    else:
        print("Invalid IP address")

except (ValueError, RuntimeError, TypeError, NameError):
    print("[-] Some Error Occured")
    print("[-] Exiting...")
