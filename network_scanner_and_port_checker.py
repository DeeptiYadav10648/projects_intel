import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import datetime

# Function to scan a single port on a host
def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.3)
            result = sock.connect_ex((ip, port))
            if result == 0:
                return port
    except Exception:
        pass
    return None

# Function to scan all specified ports on a host
def scan_host(ip, ports):
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in ports]
        for future in futures:
            port = future.result()
            if port:
                open_ports.append(port)
    return open_ports

# Function to scan a network range
def scan_network(network, ports):
    results = {}
    try:
        net = ipaddress.ip_network(network, strict=False)
        for ip in net.hosts():
            ip_str = str(ip)
            print(f"Scanning {ip_str}...")
            open_ports = scan_host(ip_str, ports)
            if open_ports:
                print(f"[+] Device {ip_str} - Open ports: {open_ports}")
                results[ip_str] = open_ports
            else:
                print(f"[-] Device {ip_str} - No open ports found.")
    except ValueError:
        print("Invalid network. Please use CIDR notation (e.g., 192.168.1.0/24).")
    return results

# Function to save results to a file
def save_results(results):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_results_{timestamp}.txt"
    with open(filename, "w") as f:
        for ip, ports in results.items():
            f.write(f"{ip}: {ports}\n")
    print(f"\nResults saved to {filename}")

if __name__ == "__main__":
    network_input = input("Enter network to scan (e.g., 192.168.1.0/24): ")
    port_range_input = input("Enter port range to scan (e.g., 20-1000): ")

    try:
        start_port, end_port = map(int, port_range_input.split('-'))
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError
        ports_to_scan = range(start_port, end_port + 1)
    except Exception:
        print("Invalid port range. Using default range 1-1024.")
        ports_to_scan = range(1, 1025)

    results = scan_network(network_input, ports_to_scan)
    if results:
        save_results(results)
    else:
        print("\nNo devices with open ports found.")
