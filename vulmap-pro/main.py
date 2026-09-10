import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from services import SERVICES
from banner import grab_banner, detect_software_version

print("= " * 50)
print("          VULNERABILITY SCANNER")
print("= " * 50)

target=input("Enter Target IP Address:")

try:
    ipaddress.ip_address(target)
    print("Valid IP Address")
except ValueError:
    print("Invalid IP Address") 
    exit()

def scan_port(port):
    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
    sock.settimeout(0.5)

    result=sock.connect_ex((target,port))

    if result == 0:
      service = SERVICES.get(port, "Unknown Service")

      print(f"Port {port} is OPEN ({service})")

      banner = grab_banner(target, port)

      software, version = detect_software_version(banner)

      print(f"Banner: {banner}")
      print(f"Software: {software}")
      print(f"Version: {version}")



    sock.close()

print("\nScanning ports...\n")

with ThreadPoolExecutor(max_workers=100) as executor:
    executor.map(scan_port,range(1,1001))

print("\nScan Completed.")





