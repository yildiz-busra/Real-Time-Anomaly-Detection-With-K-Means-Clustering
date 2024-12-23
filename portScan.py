from scapy.all import sr1, IP, TCP

target_ip = "192.168.111.129"
for port in range(1, 1024): 
    packet = IP(dst=target_ip)/TCP(dport=port, flags='S')
    response = sr1(packet, timeout=0.5, verbose=False)
    if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
        print(f"Port {port} is open")
