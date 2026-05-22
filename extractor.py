from scapy.all import PcapReader
from collections import defaultdict

import pandas as pd
import numpy as np

# ==========================================
# FEATURE EXTRACTOR
# ==========================================

def extract_features(

        pcap_file,

        output_csv="flows.csv"
):

    flows = defaultdict(lambda: {

        "start_time": None,

        "end_time": None,

        "total_packets": 0,

        "total_bytes": 0,

        "syn_count": 0,

        "ack_count": 0,

        "total_packet_size": 0,

        "protocol": 0,

        "dst_port": 0
    })

    # ==========================================
    # READ PCAP
    # ==========================================

    with PcapReader(pcap_file) as packets:

        packet_count = 0

        for packet in packets:

            try:

                packet_count += 1

                # LIMIT FOR SPEED

                if packet_count > 5000:

                    break

                # ONLY IP PACKETS

                if not packet.haslayer("IP"):

                    continue

                ip = packet["IP"]

                src_ip = ip.src

                dst_ip = ip.dst

                protocol = ip.proto

                syn_flag = 0

                ack_flag = 0

                dst_port = 0

                # ==========================================
                # TCP
                # ==========================================

                if packet.haslayer("TCP"):

                    tcp = packet["TCP"]

                    dst_port = tcp.dport

                    flags = tcp.flags

                    if flags & 0x02:

                        syn_flag = 1

                    if flags & 0x10:

                        ack_flag = 1

                # ==========================================
                # UDP
                # ==========================================

                elif packet.haslayer("UDP"):

                    udp = packet["UDP"]

                    dst_port = udp.dport

                # ==========================================
                # FLOW KEY
                # ==========================================

                flow_key = (

                    src_ip,

                    dst_ip,

                    protocol
                )

                flow = flows[flow_key]

                pkt_time = float(packet.time)

                pkt_size = len(packet)

                # ==========================================
                # TIME
                # ==========================================

                if flow["start_time"] is None:

                    flow["start_time"] = pkt_time

                flow["end_time"] = pkt_time

                # ==========================================
                # COUNTERS
                # ==========================================

                flow["total_packets"] += 1

                flow["total_bytes"] += pkt_size

                flow["syn_count"] += syn_flag

                flow["ack_count"] += ack_flag

                flow["total_packet_size"] += pkt_size

                flow["protocol"] = protocol

                flow["dst_port"] = dst_port

            except:

                continue

    # ==========================================
    # CREATE RECORDS
    # ==========================================

    records = []

    for key, flow in flows.items():

        try:

            duration = (

                flow["end_time"]

                -

                flow["start_time"]
            )

            if duration <= 0:

                duration = 0.000001

            flow_bytes_sec = (

                flow["total_bytes"] / duration
            )

            flow_packets_sec = (

                flow["total_packets"] / duration
            )

            avg_packet_size = (

                flow["total_bytes"]

                /

                flow["total_packets"]
            )

            packet_length_mean = (

                flow["total_packet_size"]

                /

                flow["total_packets"]
            )

            records.append({

                "Src IP": key[0],

                "Dst IP": key[1],

                "Flow Duration": float(duration),

                "Flow Bytes/s": float(flow_bytes_sec),

                "Flow Packets/s": float(flow_packets_sec),

                "SYN Flag Count": int(flow["syn_count"]),

                "ACK Flag Count": int(flow["ack_count"]),

                "Packet Length Mean": float(packet_length_mean),

                "Average Packet Size": float(avg_packet_size),

                "Protocol": int(flow["protocol"]),

                "Dst Port": int(flow["dst_port"])
            })

        except:

            continue

    # ==========================================
    # DATAFRAME
    # ==========================================

    df = pd.DataFrame(records)

    df.replace([np.inf, -np.inf], 0, inplace=True)

    df.fillna(0, inplace=True)

    # ==========================================
    # SAVE CSV
    # ==========================================

    df.to_csv(output_csv, index=False)

    return df

# ==========================================
# TEST
# ==========================================

if __name__ == "__main__":

    extract_features(

        "udp_flood.pcap",

        "flows.csv"
    )

    print("CSV generated successfully")