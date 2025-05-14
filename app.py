import sys
import socket
import csv
import json
from scapy.all import ARP, Ether, srp
from scapy.layers.inet import IP, ICMP
from concurrent.futures import ThreadPoolExecutor
import ipaddress

# Function to scan the network using ARP requests
def arp_scan(network):
    print(f"Scanning network: {network}...")

    # Create ARP request packet
    arp_request = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
    packet = ether / arp_request

    # Send and receive packets
    result = srp(packet, timeout=3, verbose=False)[0]

    # Parse the results
    devices = []
    for sent, received in result:
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'hostname': resolve_hostname(received.psrc)
        })

    return devices

# Function to resolve hostname from IP address
def resolve_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return "Unknown"

# Function to perform ICMP ping sweep
def ping_sweep(network):
    print(f"Pinging network: {network}...")

    # Generate list of IPs in the network
    network = ipaddress.ip_network(network, strict=False)
    ip_list = [str(ip) for ip in network.hosts()]

    # Use ThreadPoolExecutor for parallel pinging
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(ping_host, ip_list))

    # Filter out non-responsive hosts
    devices = [res for res in results if res is not None]

    return devices

# Function to ping a single host
def ping_host(ip):
    try:
        packet = IP(dst=ip) / ICMP()
        response = srp(packet, timeout=1, verbose=False)[0]

        if response:
            mac = get_mac_address(ip)
            hostname = resolve_hostname(ip)
            return {'ip': ip, 'mac': mac, 'hostname': hostname}
    except Exception as e:
        print(f"Error pinging {ip}: {e}")
    return None

# Function to get MAC address using ARP
def get_mac_address(ip):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=False)
        if ans:
            return ans[0][1].hwsrc
        return "Unknown"
    except Exception as e:
        print(f"Error getting MAC address for {ip}: {e}")
        return "Unknown"

# Function to save results to a JSON file
def save_to_json(devices, filename="network_devices.json"):
    with open(filename, 'w') as f:
        json.dump(devices, f, indent=4)
    print(f"Results saved to {filename}")

# Function to save results to a CSV file
def save_to_csv(devices, filename="network_devices.csv"):
    fieldnames = ['ip', 'mac', 'hostname']
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for device in devices:
            writer.writerow(device)
    print(f"Results saved to {filename}")

# Main function
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python network_scanner.py <network>")
        print("Example: python network_scanner.py 192.168.1.0/24")
        sys.exit(1)

    network = sys.argv[1]

    # Perform ARP scan
    print("Starting ARP scan...")
    arp_devices = arp_scan(network)
    print(f"Found {len(arp_devices)} devices via ARP.")

    # Perform ICMP ping sweep
    print("Starting ICMP ping sweep...")
    ping_devices = ping_sweep(network)
    print(f"Found {len(ping_devices)} devices via ICMP.")

    # Combine results
    all_devices = arp_devices + ping_devices
    all_devices = {device['ip']: device for device in all_devices}.values()  # Remove duplicates

    # Save results to JSON and CSV
    save_to_json(list(all_devices))
    save_to_csv(list(all_devices))