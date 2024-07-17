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

resp = int(input("""\nPlease enter the type of scan you want to run:
                1) SYN ACK Scan
                2) UDP Scan
                3) Comprehensive Scan
Option: """))
print(f"You have selected Option {resp}")

if resp == 1:
    print(f"Nmap Version: {scanner.nmap_version()}")
    scanner.scan(ip_addr, "1-1024", "-v", "-sS")
    print(scanner.scaninfo())
    print(f"IP Status: {scanner[ip_addr].state()}")
    print(scanner[ip_addr].all_protocols())
    print(f"Open Ports: {scanner[ip_addr]["tcp"].keys()}")