#!/usr/bin/env python3
import subprocess
import time
import os
import argparse
import signal
import sys

def run_command(command, background=False):
    """Run a shell command"""
    if background:
        return subprocess.Popen(command, shell=True)
    else:
        subprocess.run(command, shell=True)

def start_mininet(delay=0):
    """Start the Mininet topology"""
    print("Starting Mininet topology...")
    mininet_process = run_command("sudo python topology.py", background=True)
    time.sleep(delay)  # Allow time for topology to initialize
    return mininet_process

def start_controller(delay=0):
    """Start the Ryu controller"""
    print("Starting Ryu controller...")
    controller_script = os.path.join(os.getcwd(), "start_controller.sh")
    os.chmod(controller_script, 0o755)  # Make executable
    controller_process = run_command(controller_script, background=True)
    time.sleep(delay)  # Allow time for controller to initialize
    return controller_process

def start_server(delay=0):
    """Start the Express server"""
    print("Starting target server...")
    server_script = os.path.join(os.getcwd(), "start_server.sh")
    os.chmod(server_script, 0o755)  # Make executable
    server_process = run_command(server_script, background=True)
    time.sleep(delay)  # Allow time for server to initialize
    return server_process

def run_syn_flood_attack(target_ip, target_port, packet_count=1000):
    """Run a SYN flood attack"""
    print(f"Running SYN flood attack against {target_ip}:{target_port}...")
    attack_script = os.path.join(os.getcwd(), "attacks/syn_flood.py")
    os.chmod(attack_script, 0o755)  # Make executable
    command = f"{attack_script} {target_ip} {target_port} -c {packet_count}"
    run_command(command)

def run_http_flood_attack(target_url, request_count=1000, method="GET"):
    """Run an HTTP flood attack"""
    print(f"Running HTTP flood attack against {target_url}...")
    attack_script = os.path.join(os.getcwd(), "attacks/http_flood.py")
    os.chmod(attack_script, 0o755)  # Make executable
    command = f"{attack_script} {target_url} -c {request_count} -m {method}"
    run_command(command)

def cleanup(processes):
    """Clean up all running processes"""
    for process in processes:
        if process:
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                process.kill()
    
    # Ensure mininet is clean
    run_command("sudo mn -c")

def main():
    parser = argparse.ArgumentParser(description="DDoS Test Environment Setup")
    parser.add_argument("--setup-only", action="store_true", help="Only setup environment without running attacks")
    parser.add_argument("--target-ip", default="10.0.0.5", help="Target IP for attacks")
    parser.add_argument("--target-port", type=int, default=3000, help="Target port for attacks")
    parser.add_argument("--attack-type", choices=["syn", "http", "udp", "all"], default="all", help="Type of attack to run")
    args = parser.parse_args()
    
    processes = []
    
    def signal_handler(sig, frame):
        print("\nCleaning up and exiting...")
        cleanup(processes)
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # Start controller first (wait 2 seconds for it to initialize)
        controller_process = start_controller(delay=2)
        processes.append(controller_process)
        
        # Start Mininet (wait 5 seconds for it to connect to controller)
        mininet_process = start_mininet(delay=5)
        processes.append(mininet_process)
        
        # Start server (wait 3 seconds for server to initialize)
        server_process = start_server(delay=3)
        processes.append(server_process)
        
        if not args.setup_only:
            # Give some time for everything to stabilize
            print("Environment setup complete. Waiting 5 seconds before running attacks...")
            time.sleep(5)
            
            if args.attack_type in ["syn", "all"]:
                run_syn_flood_attack(args.target_ip, args.target_port)
                time.sleep(2)
            
            if args.attack_type in ["http", "all"]:
                target_url = f"http://{args.target_ip}:{args.target_port}"
                run_http_flood_attack(target_url)
                time.sleep(2)
            
            if args.attack_type in ["udp", "all"]:
                attack_script = os.path.join(os.getcwd(), "attacks/udp_flood.py")
                os.chmod(attack_script, 0o755)
                command = f"{attack_script} {args.target_ip} {args.target_port} -c 1000"
                run_command(command)
        
        print("Press Ctrl+C to exit")
        while True:
            time.sleep(1)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        cleanup(processes)

if __name__ == "__main__":
    main()