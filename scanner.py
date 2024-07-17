import nmap

# Create a Nmap port object
scanner = nmap.PortScanner()

print("Simple Python Nmap automation tool")
print("Developed as part of freeCodeCamp's 'Developing an Nmap Scanner - Python for Penetration Testing' series ")
print("<------------------------------------------------------------------------------------------------------->")

# IP address input from the user
ip_addr = input("Please enter the IP address you want to scan: ")

print(f"The IP address you entered is: {ip_addr}")
type(ip_addr)

# Options menu
resp = int(input("""\nPlease enter the type of scan you want to run:
                1) TCP SYN ACK Scan
                2) UDP Scan
                3) Comprehensive Scan
Option: """))
print(f"You have selected Option {resp}")

if resp == 1:
    # Nmap scanner version
    print(f"Nmap Version: {scanner.nmap_version()}")

    # Scan from ports 1-1024, verbose mode (-v), TCP SYN ACK scan (-sS)
    scanner.scan(ip_addr, "1-1024", "-v", "-sS")
    print(scanner.scaninfo())

    # IP address status
    print(f"IP Status: {scanner[ip_addr].state()}")

    # All available network protocols
    print(f"Protocols: {scanner[ip_addr].all_protocols()}")

    # All open TCP ports
    print(f"Open Ports: {scanner[ip_addr]["tcp"].keys()}")
elif resp == 2:
    # Nmap scanner version
    print(f"Nmap Version: {scanner.nmap_version()}")

    # From ports 1-1024, verbose mode (-v), UDP scan (-sU)
    scanner.scan(ip_addr, "1-1024", "-v", "-sU")
    print(scanner.scaninfo())

    # IP address status
    print(f"IP Status: {scanner[ip_addr].state()}")

    # All available network protocols
    print(f"Protocols: {scanner[ip_addr].all_protocols()}")

    # All open UDP ports
    print(f"Open Ports: {scanner[ip_addr]["udp"].keys()}")
elif resp == 3:
    # Nmap scanner version
    print(f"Nmap Version: {scanner.nmap_version()}")

    # Scan from ports 1-1024, verbose mode (-v), TCP SYN ACK scan (-sS), service enumeration (-sV), default scripts (-sC), aggressive mode (-A), operating system scan (-O)
    scanner.scan(ip_addr, "1-1024", "-v", "-sS -sV -sC -A -O")
    print(scanner.scaninfo())

    # IP address status
    print(f"IP Status: {scanner[ip_addr].state()}")

    # All available network protocols
    print(f"Protocols: {scanner[ip_addr].all_protocols()}")

    # All open UDP ports
    print(f"Open Ports: {scanner[ip_addr]["tcp"].keys()}")
else:
    # If user enters a number that isn't a valid option
    print("Invalid option selected! Please re-run the program again!")
