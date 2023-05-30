import argparse
import os, sys
import signal
import argparse
import scapy
import threading
# import libpcap

# libcap (y libnet) o hacerlo directamente en C 
# arp comando para ver la tabla de arp
# devdungeon libcap


# Every 45 seconds, refresh the ARP table
def ft_arp_refresh(ip_src, mac_src, ip_dst, mac_dst):
    print("Free the arp tables")
    print(f"{ip_src} {mac_dst}")

    while True: #not event.is_set():
        pass
    exit(0)

def ft_sigint_handler(sig, frame):
    print("Free the arp tables")
    exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ARP spoofer, ./inuisitor <IP-src> <MAC-src> <IP-target> <MAC-target>')
    parser.add_argument('addresses', action='store', nargs=4, help="<IP-src> <MAC-src> <IP-target> <MAC-target>")

    args = parser.parse_args()
    signal.signal(signal.SIGINT, ft_sigint_handler)

    ip_src = args.addresses[0]
    mac_src = args.addresses[1]
    ip_dst = args.addresses[2]
    mac_dst = args.addresses[3]
    
    x = threading.Thread(target=ft_arp_refresh, args=(ip_src, mac_src, ip_dst, mac_dst, ))
    x.start()
    x.join()
    while True:
        pass