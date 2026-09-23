
from scapy.all import sniff, IP, TCP, UDP
import csv
import os
from datetime import datetime

from pathlib import Path

FILE_NAME = str(
    Path(__file__).resolve().parent / "network_traffic.csv"
)

print("======================================")
print(" REAL NETWORK TRAFFIC COLLECTOR")
print("======================================")
print("Capturing IP traffic from your laptop...")
print("Press CTRL + C to stop.\n")

# Open CSV file
file_exists = os.path.isfile(FILE_NAME)

csv_file = open(FILE_NAME, "a", newline="")

writer = csv.writer(csv_file)

# Add column headings only for a new file
if not file_exists:

    writer.writerow([
        "Timestamp",
        "Source_IP",
        "Destination_IP",
        "Protocol",
        "Source_Port",
        "Destination_Port",
        "Packet_Size"
    ])


def process_packet(packet):

    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    packet_size = len(packet)

    protocol = "OTHER"
    source_port = ""
    destination_port = ""

    if TCP in packet:

        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:

        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    writer.writerow([
        timestamp,
        source_ip,
        destination_ip,
        protocol,
        source_port,
        destination_port,
        packet_size
    ])

    csv_file.flush()

    print(
        source_ip,
        "->",
        destination_ip,
        "|",
        protocol,
        "|",
        packet_size,
        "bytes"
    )


try:

    sniff(
        prn=process_packet,
        store=False
    )

except KeyboardInterrupt:

    print("\nCapture stopped by user.")

finally:

    csv_file.close()
    print("Traffic saved to", FILE_NAME)