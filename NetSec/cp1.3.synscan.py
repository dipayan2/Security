from scapy.all import *

import sys

def debug(s):
    print('#{0}'.format(s))
    sys.stdout.flush()

if __name__ == "__main__":
    conf.iface = sys.argv[1]
    ip_addr = sys.argv[2]

    my_ip = get_if_addr(sys.argv[1])
    
    # SYN scan
    for p in range(1, 1025):
        if (p*8)%1024==0:
            print(f"# {p*100//1024}% complete with scan")
        packet = IP(src=my_ip, dst=ip_addr) / TCP(sport=1234, dport=p, flags="S")
        resp = sr1(packet, verbose=0, timeout=.22)
        if resp and (TCP in resp) and (resp[TCP].flags.S and resp[TCP].flags.A):
            rstPacket = IP(src=my_ip, dst=ip_addr) / TCP(sport=1234, dport=p, flags="R")
            send(rstPacket, verbose=0)
            print(f"{ip_addr},{p}")


