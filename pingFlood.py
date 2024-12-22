from scapy.all import send, IP, ICMP

target_ip = "10.0.2.12"
packet = IP(dst=target_ip)/ICMP()

send(packet, count=1000, verbose=False)  # Adjust `count` for duration
