import pandas as pd
import subprocess
from datetime import datetime
from scapy.all import rdpcap, IP, TCP
import os

# Process the .pcap file with Argus
def process_with_argus(pcap_file):
    argus_output = "argus_output.csv"
    # Run Argus to generate flow data
    subprocess.run(f"argus -r {pcap_file} -w temp.argus", shell=True)
    # Convert Argus output to CSV
    subprocess.run(f"ra -r temp.argus -c , -s stime proto state dur sbytes dbytes sttl dttl sloss dloss sload dload > {argus_output}", shell=True)
    # Load Argus data into a DataFrame
    argus_data = pd.read_csv(argus_output, delim_whitespace=True, skiprows=1, names=[
    "stime", "proto", "state", "dur", "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss", "sload", "dload"])
    # Clean up temporary files
    os.remove("temp.argus")
    os.remove(argus_output)
    return argus_data

# Process the .pcap file with Zeek
def process_with_zeek(pcap_file):
    zeek_output_dir = "zeek_output"
    # Create the output directory if it doesn't exist
    if not os.path.exists(zeek_output_dir):
        os.makedirs(zeek_output_dir)
    # Run Zeek to generate logs
    subprocess.run(f"zeek -r {pcap_file} -C {zeek_output_dir}", shell=True)
    # Load Zeek logs into DataFrames
    conn_log_path = os.path.join(zeek_output_dir, "conn.log")
    http_log_path = os.path.join(zeek_output_dir, "http.log")
    ftp_log_path = os.path.join(zeek_output_dir, "ftp.log")

    if os.path.exists(conn_log_path):
        conn_log = pd.read_csv(conn_log_path, delimiter="\t", comment="#")
        # Rename columns for consistency
        conn_log.rename(columns={
            "ts": "stime",
            "orig_pkts": "Spkts",
            "resp_pkts": "Dpkts",
            "orig_ip_bytes": "smeansz",
            "resp_ip_bytes": "dmeansz",
            "proto": "proto",
        }, inplace=True)
    else:
        conn_log = pd.DataFrame()

    conn_data = conn_log[["stime", "service", "Spkts", "Dpkts", "smeansz", "dmeansz", "proto"]]

    if os.path.exists(http_log_path):
        http_log = pd.read_csv(http_log_path, delimiter="\t", comment="#")
        # Rename columns for consistency
        http_log.rename(columns={
            "ts": "stime",
            "proto": "proto",
            "request_body_len": "res_bdy_le",
            "method": "ct_ftp_http",
            "trans_depth": "trans_dept"
        }, inplace=True)
    else:
        http_log = pd.DataFrame()

    http_data = http_log[["stime", "proto", "res_bdy_le", "ct_ftp_http", "trans_dept"]]

    if os.path.exists(ftp_log_path):
        ftp_log = pd.read_csv(ftp_log_path, delimiter="\t", comment="#")
        # Rename columns for consistency
        ftp_log.rename(columns={
            "ts": "stime",
            "user": "is_ftp_login",
            "command": "ct_ftp_cmd"
        }, inplace=True)
    else:
        ftp_log = pd.DataFrame()
    ftp_data = ftp_log[["stime", "is_ftp_login", "ct_ftp_cmd"]]

    zeek_data = conn_data.merge(http_data, on="stime", direction="nearest", tolerance=pd.Timedelta("1ms"), how="outer")
    zeek_data = zeek_data.merge(ftp_data, on="stime", direction="nearest", tolerance=pd.Timedelta("1ms"), how="outer" )
    zeek_data.fillna(0, inplace=True)
    return zeek_data

# Process the .pcap file with Scapy
def process_with_scapy(pcap_file):
    packets = rdpcap(pcap_file)
    scapy_data = []
    Sjit = []
    Djit = []
    synack_times = []
    ackdat_times = []
    tcprtt_times = []
    Sintpkt = []
    Dintpkt = []

    for i in range(1, len(packets)):
        prev_packet = packets[i - 1]
        curr_packet = packets[i]

        if IP in curr_packet and TCP in curr_packet:
            # Calculate interpacket arrival times
            Sintpkt_value = abs(curr_packet.time - prev_packet.time)
            Dintpkt_value = Sintpkt_value  # Assuming symmetric interpacket times

            Sintpkt.append(Sintpkt_value)
            Dintpkt.append(Dintpkt_value)

            # Calculate jitter (Sjit and Djit)
            if IP in prev_packet and TCP in prev_packet:
                Sjit_value = abs(curr_packet.time - prev_packet.time)
                Djit_value = Sjit_value  # Assuming symmetric jitter
            else:
                Sjit_value = 0
                Djit_value = 0

            Sjit.append(Sjit_value)
            Djit.append(Djit_value)

            # Check if source and destination IPs and ports are equal
            is_sm_ips_ports = 1 if packet[IP].src == packet[IP].dst and packet[TCP].sport == packet[TCP].dport else 0

            # Calculate TCP connection setup times (synack, ackdat, tcprtt)
            if curr_packet[TCP].flags == 'S':  # SYN packet
                syn_time = curr_packet.time
            elif curr_packet[TCP].flags == 'SA':  # SYN-ACK packet
                synack_time = curr_packet.time
                synack_times.append(synack_time - syn_time)
            elif curr_packet[TCP].flags == 'A':  # ACK packet
                ack_time = curr_packet.time
                ackdat_times.append(ack_time - synack_time)
                tcprtt_times.append((synack_time - syn_time) + (ack_time - synack_time))

            # Append packet data to scapy_data
            scapy_data.append({
                "stime": datetime.fromtimestamp(curr_packet.time).strftime("%Y-%m-%d %H:%M:%S"),
                "proto": curr_packet.getfield('proto').i2s(curr_packet[IP].proto),
                "swin": curr_packet[TCP].window,
                "dwin": curr_packet[TCP].window,
                "stcpb": curr_packet[TCP].seq,
                "dtcpb": curr_packet[TCP].ack,
                "smeansz": len(curr_packet[IP]),
                "dmeansz": len(curr_packet[IP]),
                "synack": synack_times[-1] if synack_times else 0,
                "ackdat": ackdat_times[-1] if ackdat_times else 0,
                "tcprtt": tcprtt_times[-1] if tcprtt_times else 0,
                "is_sm_ips_ports": is_sm_ips_ports,
            })

    # Add jitter columns to the DataFrame
    scapy_data = pd.DataFrame(scapy_data)
    scapy_data["Sjit"] = Sjit
    scapy_data["Djit"] = Djit
    scapy_data["Sintpkt"] = Sintpkt
    scapy_data["Dintpkt"] = Dintpkt
    return scapy_data

def calculate_ct_state_ttl(ttl_data):
    # Define TTL ranges
    ttl_ranges = [
        (0, 32),
        (33, 64),
        (65, 128),
        (129, 255),
    ]
    # Initialize a dictionary to store counts
    ct_state_ttl = {}
    # Iterate through the TTL data
    for _, row in ttl_data.iterrows():
        sttl = row["sttl"]
        dttl = row["dttl"]
        # Determine the TTL range for source and destination
        sttl_range = next((f"{low}-{high}" for low, high in ttl_ranges if low <= sttl <= high), "unknown")
        dttl_range = next((f"{low}-{high}" for low, high in ttl_ranges if low <= dttl <= high), "unknown")
        # Update the count for each state and TTL range
        key = (sttl_range, dttl_range)
        if key not in ct_state_ttl:
            ct_state_ttl[key] = 1
        else:
            ct_state_ttl[key] += 1
    return ct_state_ttl

# Merge data from Argus, Zeek, and Scapy
def merge_data(argus_data, zeek_data, scapy_data):
    # Merge Argus and Scapy data on timestamp and connection details
    merged_data = pd.merge_asof(scapy_data, argus_data, on="stime", direction="nearest", tolerance=pd.Timedelta("1ms"), how="outer")
    # Merge Zeek data
    merged_data = pd.merge_asof(merged_data, zeek_data, on="stime", direction="nearest", tolerance=pd.Timedelta("1ms"), how='outer')
    merged_data = merged_data.fillna(0)
    return merged_data

def final_data(pcap_file):
    argus_data = process_with_argus(pcap_file)
    zeek_data = process_with_zeek(pcap_file)
    scapy_data = process_with_scapy(pcap_file)
    ct_state_tll = calculate_ct_state_ttl(argus_data[["stll", "dtll"]])
    ct_state_ttl_df = pd.DataFrame(list(ct_state_ttl.items()), columns=["TTL_Range","Count"])

    merged_data = merge_data(argus_data, zeek_data, scapy_data)
    merged_data["ct_state_tll"] = ct_state_tll_df["Count"]

    merged_data = merged_data.fillna(0)
    return merged_data.to_csv("features.csv", index=False)