import socket
from threading import Thread

target = input("Enter target IP: ")
ports = range(1, 1025)

def scan_port(port):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((target, port))
        
        try:
            banner = sock.recv(1024).decode().strip()
        except:
            banner = "No banner"
        
        print(f"[+] Port {port} is open | Service: {banner}")
        sock.close()
    except:
        pass

threads = []

for port in ports:
    t = Thread(target=scan_port, args=(port,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

print("Scan completed.")