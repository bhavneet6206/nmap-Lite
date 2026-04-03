import sys
import socket
from concurrent.futures import ThreadPoolExecutor 

if len(sys.argv) == 4:
    target = socket.gethostbyname(sys.argv[1])
    x = int(sys.argv[2])
    y = int(sys.argv[3])
    socket.setdefaulttimeout(1)

else:
    print("Enter valid number of argument in the form of python3 pscanner.py <ip> <start port> <end port>.")
    sys.exit()

def scan_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        result = s.connect_ex((target, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
                try:
                    s.send(b"hello\r\n")
                    banner = s.recv(1024).decode(errors= "ignore").strip()
                    if banner:
                        banner = banner.split()[0]
                    else:
                        banner = "NoBanner"
                    print(f"Port - {port} Service - {service} {banner}.")
                except OSError:
                    print(f"Port - {port} Service - {service}.")
            except OSError:
                print(f"Port - {port} Service - Unknown.")
        else:
            pass

try:
    with ThreadPoolExecutor(max_workers= 100) as executor:
        executor.map(scan_port, range(x, y + 1))

except KeyboardInterrupt:
    print("\nCtrl + c ends the scan.")










































