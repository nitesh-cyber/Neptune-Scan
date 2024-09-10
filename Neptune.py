import argparse
import logging
import time
import os
from scapy.all import IP, TCP, UDP, ICMP, sr1, sr
from concurrent.futures import ThreadPoolExecutor

def run_scripts(target_ip, port):
    print(f"Running scripts on {target_ip}:{port}")

def banner():
    print("""
    _   _           _                       ____                      
   | \ | |         | |                     / ___|  __ _  _ __  _   _  
   |  \| |  _   _  | |_    ___    _ __     | |    / _` || '__|| | | | 
   | . ` | | | | | | __|  / _ \  | '_ \    | |___| (_| || |   | |_| | 
   |_| \_| |_| |_|  \__|  \___/  |_| |_|    \____|\__,_||_|    \__, | 
                                                             |___/  
            Neptune Scan - Advanced Port Scanning Tool
                Created by Nitesh Kumar Sah
    """)

def syn_scan(target_ip, start_port, end_port, verbose=False):
    open_ports = []
    for port in range(start_port, end_port + 1):
        pkt = IP(dst=target_ip)/TCP(dport=port, flags='S')
        response = sr1(pkt, timeout=1, verbose=verbose)
        if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
            open_ports.append(port)
    return open_ports

def udp_scan(target_ip, start_port, end_port, verbose=False):
    open_ports = []
    for port in range(start_port, end_port + 1):
        pkt = IP(dst=target_ip)/UDP(dport=port)
        answered, unanswered = sr(pkt, timeout=1, verbose=verbose)
        for send_pkt, response in answered:
            if response.haslayer(ICMP) and response[ICMP].type == 3 and response[ICMP].code in [1, 2, 3, 9, 10, 13]:
                pass
            else:
                open_ports.append(port)
        if not answered:
            open_ports.append(port)
    return open_ports

def os_fingerprinting(target_ip, verbose=False):
    pkt = IP(dst=target_ip)/TCP(dport=80, flags='S')
    response = sr1(pkt, timeout=1, verbose=verbose)
    
    if response:
        ttl = response.ttl
        window_size = response[TCP].window
        os_guess = "Unknown OS"
        if ttl <= 64:
            os_guess = "Linux/Unix"
        elif ttl > 64 and ttl <= 128:
            os_guess = "Windows"
        elif ttl > 128:
            os_guess = "FreeBSD/MacOS"
        
        print(f"OS Fingerprint Guess: {os_guess}")
        print(f"TTL: {ttl}, Window Size: {window_size}")
    else:
        print("No response, unable to fingerprint OS")

def perform_traceroute(target_ip, verbose=False):
    print("Performing Traceroute...")
    result, _ = sr(IP(dst=target_ip)/ICMP(), timeout=2, verbose=verbose)
    for sent, received in result:
        print(f"{sent[IP].src} -> {received[IP].dst}")

def service_detection(target_ip, port, verbose=False):
    pkt = IP(dst=target_ip)/TCP(dport=port, flags='S')
    response = sr1(pkt, timeout=1, verbose=verbose)
    
    if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
        service = "Unknown"
        return f"Port {port} - Service: {service}"
    return None

def firewall_detection(target_ip, start_port, end_port, verbose=False):
    print("Performing Firewall Detection...")
    for port in range(start_port, end_port + 1):
        pkt = IP(dst=target_ip)/TCP(dport=port, flags='S')
        response = sr1(pkt, timeout=1, verbose=verbose)
        if response and response.haslayer(ICMP):
            print(f"Port {port} - Firewall/Filter detected")
            break

def check_root():
    if os.geteuid() != 0:
        print("This script must be run as root. Please use sudo.")
        exit()

def scan_ports(target_ip, start_port, end_port, udp, verbose):
    if udp:
        return udp_scan(target_ip, start_port, end_port, verbose)
    else:
        return syn_scan(target_ip, start_port, end_port, verbose)

def main():
    check_root()
    parser = argparse.ArgumentParser(description="Neptune Scan - Advanced Port Scanning Tool")
    parser.add_argument("target", help="Target IP address to scan")
    parser.add_argument("port_range", help="Port range in the format <start_port-end_port>")
    parser.add_argument("-T", "--threads", type=int, default=1, help="Number of threads to use")
    parser.add_argument("--udp", action="store_true", help="Enable UDP scanning")
    parser.add_argument("--os-fingerprint", action="store_true", help="Enable OS fingerprinting")
    parser.add_argument("--traceroute", action="store_true", help="Perform traceroute")
    parser.add_argument("--service-detect", action="store_true", help="Enable service detection")
    parser.add_argument("--firewall-detect", action="store_true", help="Detect presence of firewalls")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO if not args.verbose else logging.DEBUG, format='%(message)s')

    try:
        start_port, end_port = map(int, args.port_range.split('-'))
        if start_port > end_port:
            raise ValueError("Start port must be less than or equal to end port.")
    except ValueError as e:
        print(f"Invalid port range format or value. {e}")
        exit()

    banner()
    start_time = time.time()

    if args.traceroute:
        perform_traceroute(args.target, args.verbose)

    if args.os_fingerprint:
        os_fingerprinting(args.target, args.verbose)

    open_ports = scan_ports(args.target, start_port, end_port, args.udp, args.verbose)

    if args.firewall_detect:
        firewall_detection(args.target, start_port, end_port, args.verbose)

    if args.service_detect:
        for port in open_ports:
            service_info = service_detection(args.target, port, args.verbose)
            if service_info:
                print(service_info)

    if open_ports:
        print(f"Open ports: {open_ports}")
    else:
        print("No open ports found")
    
    end_time = time.time()
    logging.info(f"Scanning completed in {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
