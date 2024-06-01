#!/usr/bin/env python3

import subprocess
from scapy.all import ARP, Ether, srp
import re

def get_default_gateway_linux():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as f:
        for line in f.readlines():
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue
            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

def arp_scan(interface):
    """Perform an ARP scan to find devices on the local network."""
    gateway = get_default_gateway_linux()
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=f"{gateway}/24")
    answered, unanswered = srp(arp_request, timeout=2, iface=interface, verbose=False)
    devices = []
    for sent, received in answered:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def main():
    # Check for root privileges
    if os.geteuid() != 0:
        print("This script must be run as root.")
        exit(1)

    # Define the network interface to use for scanning
    interface = input("Enter the network interface (e.g., wlan0): ")

    print("Starting ARP scan...")
    devices = arp_scan(interface)

    print("Connected devices:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")

    # Optional: Use arp-scan for additional information
    print("Running arp-scan for additional details...")
    result = subprocess.run(['arp-scan', '-l', '-I', interface], stdout=subprocess.PIPE)
    print(result.stdout.decode('utf-8'))

if __name__ == '__main__':
    main()
