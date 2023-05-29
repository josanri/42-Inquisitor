import argparse
import os, sys
import signal
import libpcap
import scapy

# libcap (y libnet) o hacerlo directamente en C 
# arp comando para ver la tabla de arp
# devdungeon libcap

def ft_sigint_handler(sig, frame):
    print("Free the arp tables")
    exit(0)

if __name__ == "__main__":
    assert  len(sys.argv) == 5, "Needs four arguments: <IP-src> <MAC-src> <IP-target> <MAC-target>"
    signal.signal(signal.SIGINT, ft_sigint_handler)
    libpcap.config(LIBPCAP=None)
    
    errbuf = None
    libpcap.lookupdev(errbuf)
    while True:
        pass