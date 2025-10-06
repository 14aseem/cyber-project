import socket, sys

def scan_port(host, port, timeout=0.8):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception as e:
        print(f"Error scanning port {port} on {host}: {e}")
        return False
    
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python server.py <host> [<start_port> <end_port>]")
        sys.exit(1)
    host = sys.argv[1]
    ports = [21,22,23,25,53,80,110,143,443,3306,3389,8080]
    print(f"Scanning {host} on {len(ports)} ports...")
    for p in ports:
        print(f" [+] {host}:{p} OPEN" if scan_port(host,p) else f" [-] {host}:{p} closed")