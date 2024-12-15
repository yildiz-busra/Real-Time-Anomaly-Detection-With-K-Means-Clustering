from scapy.all import sniff, PcapWriter, IP, TCP, UDP, DNS, Raw
import logging
import datetime
import base64

logging.basicConfig(
    filename="detailedActivity.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

pcapFile= "detailedTraffic"
pcapWriter = PcapWriter(pcapFile, append=True, sync=True)



def extractPacketDetails(packet):

    details = {}

    details["time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    details["summary"] = packet.summary()

    if IP in packet:
        layIP = packet[IP]
        details["srcIP"] = layIP.src
        details["dstIP"] = layIP.dst
        details["protocol"] = layIP.proto

    if TCP in packet:
        layTCP = packet[TCP]
        details["srcPort"] = layTCP.sport
        details["dstPort"] = layTCP.dport
        details["flags"] = layTCP.flags

    if UDP in packet:
        layUDP = packet[UDP]
        details["srcPort"] = layUDP.sport
        details["dstPort"] = layUDP.dport

    if DNS in packet:
        layDNS = packet[DNS]
        if layDNS.qd:
            details["dnsQuery"] = layDNS.qd.qname.decode()

    if Raw in packet:
        rawData = packet[Raw].load
        details["payload"] = base64.b64encode(rawData).decode("utf-8")

    return details

def processPacket(packet):
    try:
        details = extractPacketDetails(packet)
        logMessage = ", ".join([f"{key}: {value}" for key, value in details.items()])
        logging.info(logMessage)

        print(logMessage)

        pcapWriter.write(packet)

    except Exception as e:
        logging.error(f"Error processing packet: {e}")

filterExp = "tcp"

print(f"Starting packet capture with filter: {filterExp}")
print("Press Ctrl+C to stop.")

try:
    sniff(filter=filterExp, prn=processPacket, store=False)
except KeyboardInterrupt:
    print("\nPacket capture stopped.")
    pcapWriter.close()
    print(f"Captured packets saved to {pcapFile}.")
    print("Detailed logs saved to detailedActivity.log.")

