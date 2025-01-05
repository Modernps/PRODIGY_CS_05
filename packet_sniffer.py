from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "Unknown"
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        payload = bytes(packet[IP].payload).decode(errors="ignore")

        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")
        print(f"Payload: {payload[:100]}")
        print("-" * 50)

def start_sniffer(interface=None):
    """
    Starts the packet sniffer.
    
    Args:
        interface (str): The network interface to sniff on (e.g., 'eth0'). If None, default is used.
    """
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    print("Packet Sniffer Tool")
    print("This tool is for educational purposes only. Ensure you have authorization to use it on a network.")
    print("-" * 50)
    interface = input("Enter the network interface to sniff on (leave blank for default): ").strip()
    start_sniffer(interface=interface if interface else None)
