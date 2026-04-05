#This servs as a stealth scanner which means it does not complete the 3 way TCP handshake
#Use in linux due to scapy limitations on Windows

import sys
from concurrent.futures import ThreadPoolExecutor 
from scapy.all import *
import socket
import threading

conf.verb = 0
result = []
lock = threading.Lock()

if len(sys.argv) == 4:
    target = socket.gethostbyname(sys.argv[1])
    x = int(sys.argv[2])
    y = int(sys.argv[3])

else:
    print("Enter valid number of argument in the form of python3 pscanner.py <ip> <start port> <end port>.")
    sys.exit()

def scan_port(port):
    status = 'Filtered'      # Default setup
    packet = IP(dst= target)/ TCP(dport = port, flags = 'S' )
    response = sr1(packet, timeout = 1, verbose = 0)
    try:
        if response:
            if response.haslayer(TCP):
                if response[TCP].flags & 0x12:      #0x12 is code for syn-ack packet so we send a reset packet so that the connection is stealthy
                    send(IP(dst= target)/ TCP(dport= port, flags='R'), verbose = 0)
                    status = 'Open'
                elif response[TCP].flags & 0x14:  #0x14 is code for reset + ack packet which means the port is closed
                    status = 'Closed'
            elif response.haslayer(ICMP):
                status = 'Filtered'    #if the response is an ICMP packet that means the port is filtered
        if response is None:
            status = 'Filtered'                
    except Exception as e:
        pass
    with lock:
        result.append((port, status))  #use threading.Lock so that multiple threads do no overwrite each other
    
try:
    with ThreadPoolExecutor(max_workers= 20) as executor: #keep max_workers lower to avoid multliple threads crashes
        executor.map(scan_port, range(x, y + 1))         

    for port, status in sorted(result):
        print(f"Port: {port} is {status}.")


except KeyboardInterrupt:
    print("\nCtrl + c ends the scan.")
