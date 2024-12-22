from scapy.all import sr1, IP, TCP

target_ip = "10.0.2.12"
for port in range(20, 1025): 
    packet = IP(dst=target_ip)/TCP(dport=port, flags='S')
    response = sr1(packet, timeout=0.5, verbose=False)
    if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
        print(f"Port {port} is open")
