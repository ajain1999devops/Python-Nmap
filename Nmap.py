import nmap

def scan_target(target):
    nm = nmap.PortScanner()
    
    # Perform port scanning
    print(f"Scanning ports on {target}...")
    nm.scan(target, arguments='-p1-65535 -sS')
    
    # Check if any open ports are found
    if nm.all_hosts():
        print("Open ports:")
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    print(f"Port: {port}, State: {nm[host][proto][port]['state']}")
    else:
        print("No open ports found.")
    
    # Perform OS detection
    print(f"\nPerforming OS detection on {target}...")
    nm.scan(target, arguments='-O')
    
    # Check if OS detection results are found
    if nm.all_hosts():
        print("OS detection results:")
        for host in nm.all_hosts():
            if 'osmatch' in nm[host]:
                for osmatch in nm[host]['osmatch']:
                    print(f"OS Name: {osmatch['name']}, Accuracy: {osmatch['accuracy']}")
            else:
                print("No OS detection results.")
    else:
        print("No hosts found for OS detection.")
    
    # Perform vulnerability testing
    print(f"\nPerforming vulnerability testing on {target}...")
    nm.scan(target, arguments='-sV --script vulners')
    
    # Check if vulnerability testing results are found
    if nm.all_hosts():
        print("Vulnerability testing results:")
        for host in nm.all_hosts():
            if 'script' in nm[host]:
                for script in nm[host]['script']:
                    print(f"Vulnerability: {script}, Result: {nm[host]['script'][script]}")
            else:
                print("No vulnerability testing results.")
    else:
        print("No hosts found for vulnerability testing.")


# Specify the target server
target_server = "192.168.1.1"

# Call the scan_target function
scan_target(target_server)
