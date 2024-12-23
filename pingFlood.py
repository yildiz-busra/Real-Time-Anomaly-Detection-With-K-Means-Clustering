from scapy.all import send, IP, ICMP

target_ip = "192.168.111.129"
packet = IP(dst=target_ip)/ICMP()

send(packet, count=5000, verbose=False)
