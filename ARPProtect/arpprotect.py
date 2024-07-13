import scapy.all as scapy
import time
import sys
import signal
import logging
import sqlite3
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger()

# ARP table to store IP-MAC mappings
arp_table = {}

# Setup database
conn = sqlite3.connect('arpshield.db', check_same_thread=False)
c = conn.cursor()
c.execute('''
          CREATE TABLE IF NOT EXISTS attacks
          (id INTEGER PRIMARY KEY, timestamp TEXT, real_mac TEXT, fake_mac TEXT, ip TEXT)
          ''')
conn.commit()

def signal_handler(sig, frame):
    logger.info('Exiting ARPShield')
    conn.close()
    sys.exit(0)

def detect_arp_spoof(packet):
    if packet.haslayer(scapy.ARP):
        if packet[scapy.ARP].op == 2:  # is-at (response)
            try:
                real_mac = arp_table[packet[scapy.ARP].psrc]
                response_mac = packet[scapy.ARP].hwsrc
                if real_mac != response_mac:
                    logger.warning(f"Possible ARP spoofing attack detected!")
                    logger.warning(f"Real MAC: {real_mac}, Fake MAC: {response_mac}")

                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    c.execute("INSERT INTO attacks (timestamp, real_mac, fake_mac, ip) VALUES (?, ?, ?, ?)",
                              (timestamp, real_mac, response_mac, packet[scapy.ARP].psrc))
                    conn.commit()
            except KeyError:
                arp_table[packet[scapy.ARP].psrc] = packet[scapy.ARP].hwsrc

def main():
    logger.info("Starting ARPShield...")
    signal.signal(signal.SIGINT, signal_handler)
    # Sniff ARP packets
    scapy.sniff(store=False, prn=detect_arp_spoof)

if __name__ == "__main__":
    main()
