#!/usr/bin/env python3

from scapy.all import sniff, Dot11
import argparse
import logging

# Configure logging
logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.INFO)

def packet_handler(packet):
    if packet.haslayer(Dot11):
        wifi_ssid = packet.info.decode() if packet.info else "<Hidden SSID>"
        logging.info(f"Captured packet from SSID: {wifi_ssid}")

        if packet.type == 2 and packet.haslayer(Dot11):  # Data frame
            src_mac = packet.addr2
            dst_mac = packet.addr1
            logging.info(f"Data frame: {src_mac} -> {dst_mac}")

def start_sniffing(interface):
    logging.info(f"Starting packet sniffing on interface {interface}")
    sniff(iface=interface, prn=packet_handler, store=0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='WiFi Packet Sniffer for Educational Purposes')
    parser.add_argument('-i', '--interface', required=True, help='Network interface to sniff on')
    args = parser.parse_args()

    try:
        start_sniffing(args.interface)
    except KeyboardInterrupt:
        logging.info("Stopping packet sniffing...")
        pass
