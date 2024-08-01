from scapy.all import sniff, Ether, IP, TCP, UDP, ARP, ICMP
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import socket
import time

# Global DataFrame to store captured packet data
data = pd.DataFrame(columns=[
    'Timestamp', 'Source MAC', 'Destination MAC', 'Source IP', 'Destination IP', 
    'Source Port', 'Destination Port', 'Protocol', 'Size', 'TCP Flags', 'ICMP Type', 'Direction'
])
total_packets = 0

def get_direction(packet):
    """
    Determine the direction of the packet (Incoming or Outgoing).
    
    Args:
        packet (scapy.packet.Packet): The captured packet.
        
    Returns:
        str: The direction of the packet ('Incoming', 'Outgoing', or 'Unknown').
    """
    try:
        host_ip = socket.gethostbyname(socket.gethostname())
        if packet.haslayer(IP):
            if packet[IP].src == host_ip:
                return 'Outgoing'
            elif packet[IP].dst == host_ip:
                return 'Incoming'
        return 'Unknown'
    except socket.error as e:
        print(f"Socket error occurred: {e}")
        return 'Unknown'

def packet_callback(packet):
    """
    Callback function to process each captured packet and store its information.
    
    Args:
        packet (scapy.packet.Packet): The captured packet.
    """
    global data, total_packets
    
    # Initialize variables
    src_mac = dst_mac = src_ip = dst_ip = protocol = direction = None
    src_port = dst_port = tcp_flags = icmp_type = None
    size = len(packet)
    timestamp = datetime.now()
    
    # Check for Ethernet layer
    if packet.haslayer(Ether):
        eth_layer = packet.getlayer(Ether)
        src_mac = eth_layer.src
        dst_mac = eth_layer.dst
    
    # Check for IP layer
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        direction = get_direction(packet)
        
        # Check for TCP/UDP layer
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            tcp_flags = tcp_layer.flags
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
        elif packet.haslayer(ICMP):
            icmp_layer = packet.getlayer(ICMP)
            icmp_type = icmp_layer.type
    elif packet.haslayer(ARP):
        protocol = 'ARP'
    elif packet.haslayer(ICMP):
        protocol = 'ICMP'
        icmp_layer = packet.getlayer(ICMP)
        icmp_type = icmp_layer.type
    
    # Create a DataFrame for the new packet
    packet_info = pd.DataFrame([{
        'Timestamp': timestamp,
        'Source MAC': src_mac,
        'Destination MAC': dst_mac,
        'Source IP': src_ip,
        'Destination IP': dst_ip,
        'Source Port': src_port,
        'Destination Port': dst_port,
        'Protocol': protocol,
        'Size': size,
        'TCP Flags': tcp_flags,
        'ICMP Type': icmp_type,
        'Direction': direction
    }])
    
    # Concatenate the new packet info with the existing DataFrame and update the total number of packets
    if not packet_info.isnull().all().all():  # Check if packet_info is not all-NA
        data = pd.concat([data, packet_info], ignore_index=True)
    total_packets += 1
    
    # Optionally print packet info
    print(f"Timestamp: {timestamp}, Source MAC: {src_mac}, Destination MAC: {dst_mac}, "
          f"Source IP: {src_ip}, Destination IP: {dst_ip}, Source Port: {src_port}, "
          f"Destination Port: {dst_port}, Protocol: {protocol}, Size: {size} bytes, "
          f"TCP Flags: {tcp_flags}, ICMP Type: {icmp_type}, Direction: {direction}")

def start_sniffing(duration):
    """
    Start packet capture for a specified duration.
    
    Args:
        duration (int): The duration for which to capture packets, in seconds.
    """
    print(f"Starting packet capture for {duration} seconds...")
    start_time = time.time()
    while (time.time() - start_time) < duration:
        sniff(prn=packet_callback, store=0, timeout=1)  # Capture packets in 1-second intervals

def analyze_data():
    """
    Analyze the captured packet data and visualize it.
    """
    global data
    
    # Save data to CSV
    data.to_csv('packet_data.csv', index=False)
    print(f"\nTotal packets captured: {total_packets}")
    print("Packet sizes:")
    print(data['Size'].describe())
    
    # Create a simple visualization
    plt.figure(figsize=(10, 6))
    data['Timestamp'] = pd.to_datetime(data['Timestamp'])
    data.set_index('Timestamp', inplace=True)
    data['Size'].plot(title='Packet Size Over Time')
    plt.xlabel('Time')
    plt.ylabel('Packet Size (bytes)')
    plt.grid(True)
    plt.show()

if __name__ == "__main__":
    capture_duration = 120  # 2 minutes
    start_sniffing(capture_duration)
    analyze_data()
