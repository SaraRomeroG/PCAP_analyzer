import pyshark
import pandas as pd
from collections import defaultdict
import geoip2.database
import argparse
import os
import sys
import logging
import json
import math
from collections import Counter
import time
import ipaddress

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

def load_config(config_path='config.json'):
    """
    Loads the configuration from the config.json file.
    :param config_path: Path to the configuration file.
    :return: Dictionary with the configuration.
    """
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"Configuration file {config_path} not found.")
        raise
    except json.JSONDecodeError:
        logging.error(f"Error parsing the configuration file {config_path}.")
        raise

def load_pcap(pcap_file):
    """
    Loads a PCAP file and returns a list of packets.
    :param pcap_file: Path to the PCAP file.
    :return: List of pyshark.packet.Packet objects.
    """
    if not os.path.exists(pcap_file):
        logging.error(f"The file {pcap_file} does not exist.")
        raise FileNotFoundError(f"The file {pcap_file} does not exist.")
    
    if not pcap_file.endswith(('.pcap', '.pcapng')):
        logging.warning(f"The file {pcap_file} does not seem to be a valid PCAP (unrecognized extension).")

    try:
        cap = pyshark.FileCapture(pcap_file, use_json=True, include_raw=False)
        for pkt in cap:
            yield pkt
        cap.close()
    except Exception as e:
        logging.error(f"Error loading PCAP file {pcap_file}: {str(e)}")
        raise RuntimeError(f"Could not load PCAP file: {str(e)}")

def normalize_data(packets):
    """
    Extracts and normalizes key data from the packets.
    :param packets: List of loaded packets.
    :return: DataFrame with normalized data.
    """
    data = []
    batch_size = 1000

    for i, pkt in enumerate(packets):
        try:
            # Define default values for ports
            source_port = None
            destination_port = None
            source_mac = None
            destination_mac = None

            # MAC addresses if Ethernet layer exists
            if hasattr(pkt, 'eth'):
                source_mac = pkt.eth.src
                destination_mac = pkt.eth.dst

            # Check if the packet has a transport layer (TCP/UDP)
            if hasattr(pkt, 'transport_layer'):
                if pkt.transport_layer:  # If it has transport layer
                    if hasattr(pkt, pkt.transport_layer):  # Verify the transport exists
                        source_port = pkt[pkt.transport_layer].srcport
                        destination_port = pkt[pkt.transport_layer].dstport

            # Store packet data
            data.append({
                'timestamp': pkt.sniff_time,
                'source_ip': pkt.ip.src if hasattr(pkt, 'ip') else None,
                'destination_ip': pkt.ip.dst if hasattr(pkt, 'ip') else None,
                'protocol': pkt.highest_layer if hasattr(pkt, 'highest_layer') else None,
                'source_port': source_port,
                'destination_port': destination_port,
                'source_mac': source_mac,
                'destination_mac': destination_mac
            })

            # Process in batches to avoid memory buildup
            if (i + 1) % batch_size == 0:
                yield pd.DataFrame(data)
                data = []

        except AttributeError:
            # Handle packets without IP layer or transport layer
            continue

    # Send the last batch if any
    if data:
            yield pd.DataFrame(data)

def get_df(pcap_file):
    """
    Processes the PCAP file and returns a concatenated DataFrame containing the packet data.
    :param pcap_file: Path to the PCAP file to be processed.
    :return: Pandas DataFrame with the normalized packet data.
    """
    packets = load_pcap(pcap_file)
    df_list = list(normalize_data(packets))
    return pd.concat(df_list, ignore_index=True) if df_list else pd.DataFrame()

def generate_statistics(df):
    """
    Generates initial statistics on network traffic.
    :param df: DataFrame with normalized data.
    :return: Dictionary with statistics.
    """
    statistics = {}

    # Protocol distribution
    statistics['protocol'] = df['protocol'].value_counts()
    print("\nProtocol distribution:")
    print(statistics['protocol'].to_string())

    # Packets sent by source and destination IP
    statistics['source_ip'] = df['source_ip'].value_counts()
    print("\nPackets sent by source IP:")
    print(statistics['source_ip'].to_string())
    statistics['destination_ip'] = df['destination_ip'].value_counts()
    print("\nPackets sent by destination IP:")
    print(statistics['destination_ip'].to_string())

    # Most used ports
    statistics['source_port'] = df['source_port'].value_counts().head(10)
    print("\nMost used source ports:")
    print(statistics['source_port'].to_string())
    statistics['destination_port'] = df['destination_port'].value_counts().head(10)
    print("\nMost used destination ports:")
    print(statistics['destination_port'].to_string())

    # Top 10 IPs with most traffic (packets)
    top_ips = pd.concat([df['source_ip'], df['destination_ip']])
    statistics['top_ips'] = top_ips.value_counts().head(10)
    print("\nTop 10 IPs with most traffic:")
    print(statistics['top_ips'].to_string())

    return statistics

def is_private_ip(ip):
    """
    Checks if an IP is private.
    :param ip: IP in string format.
    :return: True if the IP is private, False otherwise.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def detect_scan(pcap_file, display_filter, config=None):
    """
    Detects scans based on a display filter.
    :param pcap_file: Path to the PCAP file.
    :param display_filter: Display filter to identify the type of scan.
    :param threshold: Number of packets allowed per IP.
    :return: Dictionary with source IPs and their number of attempts.
    """
    if config is None:
        config = load_config()
    threshold = config.get('scan_threshold', 10)

    cap = pyshark.FileCapture(pcap_file, display_filter=display_filter)
    ip_count = defaultdict(int)

    for pkt in cap:
        if hasattr(pkt, 'ip'):
            source_ip = pkt.ip.src
            ip_count[source_ip] += 1

    cap.close()

    # Filter IPs that exceed the threshold
    potential_attackers = {ip: count for ip, count in ip_count.items() if count >= threshold}
    return potential_attackers

def advanced_statistics(df):
    """
    Generates advanced statistics on IP connections and average connection duration.
    :param df: DataFrame with normalized data.
    :return: Dictionary with advanced statistics.
    """
    statistics = {}

    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # 1. Calculate average duration of connections between (source_ip, destination_ip) pairs
    connection_times = df.groupby(['source_ip', 'destination_ip'])['timestamp'].agg(['min', 'max'])
    connection_times['duration'] = (connection_times['max'] - connection_times['min']).dt.total_seconds()
    statistics['average_connection_duration'] = connection_times['duration'].mean()
    print("\nAverage duration of connections (in seconds):")
    print(f"{statistics['average_connection_duration']:.2f}")

    # 2. Top 10 longest connections by duration
    statistics['longest_connections'] = connection_times.sort_values(by=['duration', 'min'], ascending=[False, True]).head(10)
    print("\nTop 10 longest connections (source IP -> destination IP):")
    print(statistics['longest_connections'].reset_index().to_string(index=False))

    # 3. Most frequent (source_ip -> destination_ip) connection pairs (reconnection frequency)
    reconnection_freq = df.groupby(['source_ip', 'destination_ip']).size().sort_values(ascending=False).head(10)
    statistics['reconnection_frequency'] = reconnection_freq
    print("\nTop 10 most frequent connection pairs (reconnection attempts):")
    print(statistics['reconnection_frequency'].reset_index().to_string(index=False))

    return statistics

def geo_locate_ip(ip, db_path="GeoLite2-City.mmdb"):
    """
    Locates an IP using the MaxMind GeoLite2 database.
    :param ip: The IP to locate.
    :param db_path: Path to the GeoIP database.
    :return: Dictionary with geographical information.
    """
    if not ip or is_private_ip(ip):
        return None

    if not os.path.exists(db_path):
        logging.error(f"GeoIP database {db_path} not found.")
        return None
    
    try:
        with geoip2.database.Reader(db_path) as reader:
            response = reader.city(ip)
            return {
                'country': response.country.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude
            }

    except Exception as e:
        return None

def detect_ddos(pcap_file, config=None):
    """
    Detects potential DDoS attacks by counting packets from each IP.
    :param pcap_file: Path to the PCAP file.
    :return: Dictionary with source IPs and destination IPs that exceed the threshold.
    """
    if config is None:
        config = load_config()
    threshold = config.get('ddos_threshold', 100)
    time_interval = config.get('time', 60)

    cap = pyshark.FileCapture(pcap_file)
    source_ip_count = defaultdict(int)
    dest_ip_count = defaultdict(int)
    start_time = time.time()

    for pkt in cap:
        if hasattr(pkt, 'ip'):
            source_ip = pkt.ip.src
            dest_ip = pkt.ip.dst
            packet_time = time.time()

            # Count packets for source IP
            if packet_time - start_time <= time_interval:
                source_ip_count[source_ip] += 1
            
            else:
                source_ip_count = defaultdict(int)
                start_time = packet_time
                source_ip_count[source_ip] += 1

             # Count packets for destination IP
            if packet_time - start_time <= time_interval:
                dest_ip_count[dest_ip] += 1
            else:
                dest_ip_count = defaultdict(int)
                start_time = packet_time
                dest_ip_count[dest_ip] += 1

    cap.close()

    # Filter IPs that exceed the packet threshold
    potential_ddos_sources = {ip: count for ip, count in source_ip_count.items() if count >= threshold}
    potential_ddos_destinations = {ip: count for ip, count in dest_ip_count.items() if count >= threshold}

    return potential_ddos_sources, potential_ddos_destinations

def get_traffic_statistics(df, db_path="GeoLite2-City.mmdb"):
    """
    Generates traffic statistics using IP geolocation.
    :param df: DataFrame with normalized data.
    :param db_path: Path to the GeoIP database.
    :return: Dictionary with traffic statistics.
    """
    statistics = {}

    # Filter public IPs (non-private)
    df['source_country'] = df['source_ip'].apply(lambda x: geo_locate_ip(x, db_path) if x and not is_private_ip(x) else None)
    df['destination_country'] = df['destination_ip'].apply(lambda x: geo_locate_ip(x, db_path) if x and not is_private_ip(x) else None)

    # Statistics on source countries
    statistics['top_source_countries'] = df['source_country'].value_counts().head(10)
    statistics['top_destination_countries'] = df['destination_country'].value_counts().head(10)

    # Statistic on IPs that connect to international destinations
    # Filter connections where the destination country is different from the source country
    international_df = df[df['source_country'] != df['destination_country']]
    international_ips = international_df['source_ip'].value_counts().head(10)
    statistics['ips_with_international_connections'] = international_ips

    # Display the statistics
    print(f"\nTop 10 source countries:")
    print(statistics['top_source_countries'].to_string())

    print(f"\nTop 10 destination countries:")
    print(statistics['top_destination_countries'].to_string())

    print(f"\nTop 10 IPs with international connections:")
    print(statistics['ips_with_international_connections'].to_string())

    return statistics

def detect_lateral_movement(df, config=None):
    """
    Detects lateral movement within the network and generates internal statistics.
    :param df: DataFrame with normalized data.
    :return: Dictionary with analysis of suspicious internal connections.
    """
    if config is None:
        config = load_config()
    target_ports = config.get('lateral_movement_ports', {})
    known_ports = set(config.get('known_ports', []))

    results = {}

    # Filter only connections between internal IPs
    df_internal = df[
        df['source_ip'].notna() &
        (df['source_ip'].str.startswith('192.168') |
         df['source_ip'].str.startswith('10.') |
         ((df['source_ip'].str.startswith('172.')) & 
          df['source_ip'].str.split('.').str[1].apply(lambda x: x.isdigit() and 16 <= int(x) <= 31 if x is not None else False))
        )
    ]

    df_internal = df_internal[
        df_internal['destination_ip'].notna() &
        (df_internal['destination_ip'].str.startswith('192.168') |
         df_internal['destination_ip'].str.startswith('10.') |
         ((df_internal['destination_ip'].str.startswith('172.')) & 
          df_internal['destination_ip'].str.split('.').str[1].apply(lambda x: x.isdigit() and 16 <= int(x) <= 31 if x is not None else False))
        )
    ]

    # Basic statistics
    results['total_internal_connections'] = len(df_internal)
    results['top_lan_ips'] = df_internal['source_ip'].value_counts().head(10)

    # Detect typical lateral movement protocols (known ports)
    protocol_connections = {}
    suspicious_ports = defaultdict(list)

    for name, port in target_ports.items():
        connections = df_internal[
            (df_internal['source_port'] == port) |
            (df_internal['destination_port'] == port)
        ]
        protocol_connections[name] = connections

        # Save ports used in these connections
        used_ports = pd.concat([
            connections['source_port'], connections['destination_port']
        ]).value_counts().head(10)
        suspicious_ports[name] = used_ports

    results['connections_by_protocol'] = {
        protocol: len(conns) for protocol, conns in protocol_connections.items()
    }

    results['ports_used_in_lateral_movement'] = dict(suspicious_ports)

    # Fan-out detection: IPs connecting to many other internal IPs
    fan_out = df_internal.groupby('source_ip')['destination_ip'].nunique().sort_values(ascending=False)
    fan_out = fan_out[fan_out > 5] 
    results['fan_out_connections'] = fan_out

    # Unusual ports detection
    unusual_connections = df_internal[
        ~df_internal['destination_port'].isin(known_ports)
    ]
    unusual_ports = unusual_connections['destination_port'].value_counts().head(10)
    results['unusual_ports'] = unusual_ports

    # IP-MAC analysis: detect IPs with multiple different MACs
    ip_mac_relations = df[['source_ip', 'source_mac']].dropna().drop_duplicates()

    # FILTER: remove rows where source_ip is empty or None
    ip_mac_relations = ip_mac_relations[ip_mac_relations['source_ip'].str.strip() != '']

    conflicts = ip_mac_relations.groupby('source_ip')['source_mac'].nunique()
    conflicts = conflicts[conflicts > 1]

    # List unique MACs for conflicting IPs
    mac_conflicts = {}
    for ip in conflicts.index:
        macs = ip_mac_relations[ip_mac_relations['source_ip'] == ip]['source_mac'].unique().tolist()
        mac_conflicts[ip] = macs

    results['ip_mac_conflicts'] = mac_conflicts

    print("\nTotal internal-to-internal connections detected:")
    print(results['total_internal_connections'])

    print("\nTop 10 internal source IPs by number of connections:")
    print(results['top_lan_ips'].to_string())

    print("\nConnections using typical lateral movement ports:")
    for protocol, count in results['connections_by_protocol'].items():
        print(f"{protocol}: {count} connections")

    print("\nTop ports used in potential lateral movement by protocol:")
    for protocol, ports in results['ports_used_in_lateral_movement'].items():
        print(f"\n{protocol} - Top ports:")
        print(ports.to_string())

    print("\nFan-out detection (IPs connecting to many internal IPs):")
    print(results['fan_out_connections'].to_string() if not fan_out.empty else "None")

    print("\nUnusual destination ports detected inside LAN:")
    print(results['unusual_ports'].to_string() if not unusual_ports.empty else "None")

    print("\nIP-MAC conflicts detected (possible spoofing or pivoting):")
    if results['ip_mac_conflicts']:
        for ip, macs in results['ip_mac_conflicts'].items():
            print(f"{ip} -> {', '.join(macs)}")
    else:
        print("None")

    return results

def calculate_entropy(text):
    """
    Calculates the Shannon entropy of a text.
    :param text: Text to analyze.
    :return: Entropy value.
    """
    if not text:
        return 0.0
    length = len(text)
    count = Counter(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in count.values())
    return entropy

def analyze_dns(pcap_file, config=None):
    """
    Analyzes DNS queries and detects suspicious domains.
    :param pcap_file: Path to the PCAP file.
    :return: Dictionary with statistics and detections.
    """
    if config is None:
        config = load_config()
    blacklist = set(config.get('malicious_domains', []))
    suspicious_tlds = config.get('suspicious_tlds', [])
    entropy_threshold = config.get('dns_entropy_threshold', 4.0)
    max_domain_length = config.get('max_domain_length', 50)

    cap = pyshark.FileCapture(pcap_file, display_filter='dns')
    dns_queries = []
    
    for pkt in cap:
        try:
            if 'DNS' in pkt:
                source_ip = pkt.ip.src if hasattr(pkt, 'ip') else None
                domain = pkt.dns.qry_name if hasattr(pkt.dns, 'qry_name') else None
                
                if source_ip and domain:
                    domain_lower = domain.lower()
                    entropy = calculate_entropy(domain_lower)
                    dns_queries.append({
                        'source_ip': source_ip,
                        'domain': domain_lower,
                        'entropy': entropy,
                        'domain_length': len(domain_lower)
                    })
        except AttributeError:
            continue

    cap.close()
    if not dns_queries:
        print("No valid DNS packets found.")
        return {}
    
    df_dns = pd.DataFrame(dns_queries)
    results = {}

    # 1. Number of DNS queries by IP
    results['queries_by_ip'] = df_dns['source_ip'].value_counts()

    # 2. Most queried domains
    results['most_queried_domains'] = df_dns['domain'].value_counts().head(10)

    # 3. IPs querying malicious domains
    if blacklist:
        df_dns['is_suspicious'] = df_dns['domain'].isin(blacklist)
        suspicious_ips = df_dns[df_dns['is_suspicious']]['source_ip'].value_counts()
        results['ips_with_suspicious_queries'] = suspicious_ips

    # 4. IPs querying domains from unusual countries (by TLD)
    df_dns['tld'] = df_dns['domain'].str.extract(r'(\.[a-z]{2,})$')
    ips_unusual_tld = df_dns[df_dns['tld'].isin(suspicious_tlds)]['source_ip'].value_counts()
    results['ips_with_unusual_tlds'] = ips_unusual_tld

    # 5. DNS tunneling detection
    df_dns['possible_tunnel'] = (df_dns['entropy'] > entropy_threshold) | (df_dns['domain_length'] > max_domain_length)
    dns_tunnels = df_dns[df_dns['possible_tunnel']][['source_ip', 'domain', 'entropy', 'domain_length']]
    results['possible_dns_tunnels'] = dns_tunnels

    # Ensure all columns are displayed
    pd.set_option('display.max_columns', None)

    print('\nQueries count per IP:')
    print(results['queries_by_ip'].to_string(index=True)) 

    print('\nMost queried domains:')
    print(results['most_queried_domains'].to_string(index=True)) 

    print('\nIPs with queries to malicious domains:')
    print(results['ips_with_suspicious_queries'].to_string(index=True)) 

    print('\nIPs with queries to unusual country TLDs:')
    print(results['ips_with_unusual_tlds'].to_string(index=True))

    print('\nDNS tunnel detection:')
    print(results['possible_dns_tunnels'].to_string(index=False))

    return results

def analyze_icmp(pcap_file, config=None):
    """
    Analyzes ICMP traffic and detects anomalies.
    :param pcap_file: Path to the PCAP file.
    :param flood_threshold: Threshold of ICMP packets per IP to consider a possible Ping Flood.
    :return: Dictionary with ICMP statistics and anomalies.
    """
    if config is None:
        config = load_config()
    time_window = config.get('time', 60)
    flood_threshold = config.get('icmp_flood_threshold', 100)

    cap = pyshark.FileCapture(pcap_file, display_filter='icmp')
    icmp_data = []

    for pkt in cap:
        try:
            if 'ICMP' in pkt and hasattr(pkt, 'ip') and hasattr(pkt.icmp, 'type'):
                icmp_data.append({
                    'timestamp': pkt.sniff_time,
                    'source_ip': pkt.ip.src,
                    'destination_ip': pkt.ip.dst,
                    'icmp_type': pkt.icmp.type
                })
        except AttributeError:
            continue

    cap.close()

    if not icmp_data:
        print("No valid ICMP packets detected.")
        return {}

    df_icmp = pd.DataFrame(icmp_data)
    df_icmp['timestamp'] = pd.to_datetime(df_icmp['timestamp'])
    results = {}

    # 1. Number of ICMP packets by source IP
    results['icmp_by_ip'] = df_icmp['source_ip'].value_counts()

    # 2. Detect possible Ping Flood
    flood_ips = []
    for ip, group in df_icmp.groupby('source_ip'):
        group_sorted = group.sort_values(by='timestamp') 
        for i in range(len(group_sorted)):
            time_window_start = group_sorted.iloc[i]['timestamp']
            time_window_end = time_window_start + pd.Timedelta(seconds=time_window)
            count_in_window = group_sorted[(group_sorted['timestamp'] >= time_window_start) & (group_sorted['timestamp'] <= time_window_end)].shape[0]

            if count_in_window > flood_threshold:
                flood_ips.append(ip)
                break 

    results['possible_ping_flood'] = flood_ips

    # 3. IPs pinging multiple destinations
    source_dest = df_icmp.groupby('source_ip')['destination_ip'].nunique()
    source_dest = source_dest[source_dest > 10]
    results['ping_to_multiple_destinations'] = source_dest

    # 4. Estimate average latency (if echo-request and echo-reply are detected)
    # This part is very basic and depends on the order in the PCAP
    df_echo = df_icmp[df_icmp['icmp_type'].isin(['8', '0'])].copy()
    df_echo['timestamp'] = pd.to_datetime(df_echo['timestamp'])
    df_echo.sort_values(by='timestamp', inplace=True)
    df_echo['difference'] = df_echo['timestamp'].diff().fillna(pd.Timedelta(seconds=0))
    results['average_latency'] = df_echo['difference'].mean()

    # 5. Detect fragmented packets
    cap_frag = pyshark.FileCapture(pcap_file, display_filter='ip.flags.mf == 1 || ip.frag_offset > 0 && icmp')
    fragmented = []

    for pkt in cap_frag:
        try:
            if hasattr(pkt, 'ip') and 'ICMP' in pkt:
                fragmented.append({
                    'source_ip': pkt.ip.src,
                    'destination_ip': pkt.ip.dst,
                    'flags': pkt.ip.flags,
                    'offset': pkt.ip.frag_offset
                })
        except AttributeError:
            continue

    cap_frag.close()
    results['icmp_fragmented'] = pd.DataFrame(fragmented)

    # 6. Compare echo-request vs. echo-reply
    type_counts = df_icmp['icmp_type'].value_counts()
    requests = type_counts.get('8', 0)
    replies = type_counts.get('0', 0)
    results['request_reply_ratio'] = f"{requests}:{replies}" if replies else f"{requests}:0 (no replies)"

    print('\n' f"ICMP packets count per source IP:")
    print(results['icmp_by_ip'].to_string(index=True))

    print('\n' f"Possible Ping Flood:")
    print(', '.join(results['possible_ping_flood']) if results['possible_ping_flood'] else "No possible ping flood detected")

    print('\nIPs pinging multiple destinations:')
    print(results['ping_to_multiple_destinations'].to_string(index=True))

    print('\nEstimated average latency:')
    print(f"{results['average_latency']} seconds")

    print('\nICMP fragmented packet detection:')
    print(results['icmp_fragmented'].to_string(index=False))

def analyze_http(pcap_file, config=None):
    """
    Analyzes HTTP sessions and detects suspicious activity.
    :param pcap_file: Path to the PCAP file.
    :param request_threshold: Number of requests in a short time considered suspicious.
    :param data_threshold: Size of POST body considered potential exfiltration.
    :return: Dictionary with HTTP statistics and anomalies.
    """
    if config is None:
        config = load_config()
    request_threshold = config.get('http_request_threshold', 20)
    data_threshold = config.get('http_data_threshold', 1000)
    
    cap = pyshark.FileCapture(pcap_file, display_filter='http')
    http_sessions = []

    for pkt in cap:
        try:
            if hasattr(pkt, 'http'):
                method = pkt.http.get('request_method', '')
                uri = getattr(pkt.http, 'request_uri', '')
                host = pkt.http.get('host', '')
                content_length = int(pkt.http.get('content_length', '0'))

                http_sessions.append({
                    'timestamp': pkt.sniff_time,
                    'source_ip': pkt.ip.src,
                    'method': method,
                    'uri': uri,
                    'host': host,
                    'content_length': content_length
                })
        except AttributeError:
            continue

    cap.close()

    df_http = pd.DataFrame(http_sessions)
    results = {}

    if df_http.empty:
        print("No HTTP sessions detected.")
        return {}
    
    df_http['timestamp'] = pd.to_datetime(df_http['timestamp'])
    df_http.sort_values(by='timestamp', inplace=True)

    # 1. Top accessed domains
    results['top_domains'] = df_http['host'].value_counts().head(10)

    # 2. Top requests by source IP
    results['requests_by_ip'] = df_http['source_ip'].value_counts().head(10)

    # 3. IPs with many requests in a short time
    ddos_suspects = []
    grouped = df_http.groupby('source_ip')

    for ip, group in grouped:
        group = group.sort_values(by='timestamp')
        time_diffs = group['timestamp'].diff().dt.total_seconds().fillna(0)
        rapid_requests = (time_diffs < 5).sum()
        if rapid_requests >= request_threshold:
            ddos_suspects.append(ip)

    results['frequent_requests'] = ddos_suspects

    # 3.1 Calculate request rate per IP (requests per minute)
    # Round timestamps down to the nearest minute
    df_http['minute'] = df_http['timestamp'].dt.floor('min')

    # Count requests per (source_ip, minute)
    requests_per_minute = df_http.groupby(['source_ip', 'minute']).size().reset_index(name='requests')

    # Compute the average number of requests per minute for each IP
    ip_request_rates = requests_per_minute.groupby('source_ip')['requests'].mean().sort_values(ascending=False)

    # Store result
    results['requests_per_minute'] = ip_request_rates

    # 4. Detect exfiltration by POST with large data
    exfiltration = df_http[
        (df_http['method'] == 'POST') & (df_http['content_length'] >= data_threshold)
    ]
    results['possible_exfiltration'] = exfiltration[['source_ip', 'host', 'uri', 'content_length']]

    # 5. Count of HTTP methods
    df_http['method'] = df_http['method'].fillna('').replace('', 'NO_METHOD')
    results['http_methods'] = df_http['method'].value_counts()

    pd.set_option('display.max_columns', None)

    print('\nTop 10 accessed domains:')
    print(results['top_domains'].to_string(index=True))  

    print('\nTop 10 requests by source IP:')
    print(results['requests_by_ip'].to_string(index=True))   

    print('\nAverage request rate per IP (requests per minute, top 10):')
    print(results['requests_per_minute'].head(10).to_string())

    print('\nIPs with many requests in a short time (possible Dos/DDoS):')
    print('\n'.join(results['frequent_requests']) if results['frequent_requests'] else 'None') 

    print('\nPossible data exfiltration via POST with large data:')
    print(results['possible_exfiltration'].to_string(index=False) if not exfiltration.empty else 'None')

    print('\nMethod count:')
    print(results['http_methods'].to_string(index=True))   

def extract_dns_domains(pcap_file):
    """
    Extracts the DNS query domains from the given PCAP file.
    :param pcap_file: Path to the PCAP file to be analyzed.
    :return: Sorted list of unique DNS query domains found in the PCAP file.
    """
    cap = pyshark.FileCapture(pcap_file, display_filter='dns')
    domains = set()

    for pkt in cap:
        try:
            if hasattr(pkt, 'dns') and hasattr(pkt.dns, 'qry_name'):
                domains.add(pkt.dns.qry_name.lower())
        except:
            continue
    cap.close()
    return sorted(domains)

def count_packets_by_ip(df):
    """
    Counts the number of packets sent and received by each IP address in the DataFrame.
    :param df: Pandas DataFrame containing the packet data with 'source_ip' and 'destination_ip' columns.
    :return: A string representing the total count of packets for each IP address, sorted in descending order.
    """
    source = df['source_ip'].value_counts()
    destination = df['destination_ip'].value_counts()
    total = (source.add(destination, fill_value=0)).sort_values(ascending=False).to_string(index=True)
    return total

def session_detail(df, ip1, ip2):
    """
    Filters and returns the sessions between two IPs (both directions).
    :param df: DataFrame containing the network traffic data.
    :param ip1: First IP address.
    :param ip2: Second IP address.
    :return: Filtered DataFrame showing the session details between the two IPs.
    """
    # Filter for sessions between ip1 and ip2 (both directions)
    filtered_df = df[
        ((df['source_ip'] == ip1) & (df['destination_ip'] == ip2)) |
        ((df['source_ip'] == ip2) & (df['destination_ip'] == ip1))
    ]

    # If the table has more than 40 rows, export it to a CSV
    if len(filtered_df) > 40:
        filtered_df.to_csv('detail.csv', index=False)
        print("\nSession detail table has been exported to 'detail.csv' because it exceeds 40 entries.")

    return filtered_df

def resolve_dns_domain(pcap_file, domain):
    """
    Resolves the IP addresses for a specific DNS domain found in the PCAP file.
    :param pcap_file: Path to the PCAP file to be analyzed.
    :param domain: The DNS domain to be resolved.
    :return: A set of unique IP addresses associated with the specified DNS domain.
    """
    cap = pyshark.FileCapture(pcap_file, display_filter='dns')
    results = set()
    for pkt in cap:
        try:
            if hasattr(pkt, 'dns') and hasattr(pkt.dns, 'qry_name') and pkt.dns.qry_name.lower() == domain.lower():
                if hasattr(pkt.dns, 'a'):
                    results.add(pkt.dns.a)
        except:
            continue
    cap.close()
    return results

def access_domain(pcap_file, domain):
    """
    Retrieves the source IP addresses that accessed a specific DNS domain in the given PCAP file.
    :param pcap_file: Path to the PCAP file to be analyzed.
    :param domain: The DNS domain to be accessed.
    :return: A set of unique source IP addresses that made DNS queries for the specified domain.
    """
    cap = pyshark.FileCapture(pcap_file, display_filter='dns')
    results = set()
    for pkt in cap:
        try:
            # Verificamos que el paquete tiene una consulta DNS
            if hasattr(pkt, 'dns') and hasattr(pkt.dns, 'qry_name'):
                # Comprobamos si la consulta DNS es para el dominio buscado
                if pkt.dns.qry_name.lower() == domain.lower():
                    # Agregar la IP de origen de la consulta (la IP que hizo la solicitud)
                    results.add(pkt.ip.src)
        except AttributeError:
            continue
    cap.close()
    return results

def find_ip(df, ip, max_results=10, output_file='results.csv'):
    """
    Searches and displays all matches for the provided IP.
    If the number of matches exceeds 'max_results', exports the results to a CSV file.
    
    :param df: DataFrame with normalized data.
    :param ip: IP to search.
    :param max_results: Limit of results before exporting to a file.
    :param output_file: Name of the file where results will be saved.
    :return: Matches for the network IP, or exports the results if exceeding the limit.
    """
    pd.set_option('display.max_columns', None)  # Show all columns

    matches = df[(df['source_ip'] == ip) | (df['destination_ip'] == ip)]
    
    # If the number of matches exceeds the limit, export to a file
    if len(matches) > max_results:
        matches.to_csv(output_file, index=False)
        print(f"Results have been exported to {output_file}.")
    else:
        print(f"{len(matches)} matches found.")
    
    return matches

def find_ip_country(df, country_name, db_path="GeoLite2-City.mmdb"):
    """
    Searches and displays all unique source or destination IPs located in a specific country.
    :param df: DataFrame with normalized data.
    :param country_name: Name of the country to search (in full text with underscores instead of spaces).
    :param db_path: Path to the GeoIP database.
    :return: Matches of unique source or destination IPs located in the specified country.
    """
    # Function to get the country from an IP
    def get_country(ip):
        try:
            country = geo_locate_ip(ip, db_path)
            return country['country'] if country else None  # If country is None, return None
        except Exception as e:
            print(f"Error geolocating IP {ip}: {e}")
            return None

    # Replace underscores with spaces in the country name input
    country_name = country_name.replace("_", " ")

    # Apply geolocation to source and destination IPs
    df['source_country'] = df['source_ip'].apply(lambda x: get_country(x) if x else None)
    df['destination_country'] = df['destination_ip'].apply(lambda x: get_country(x) if x else None)

    # Filter the IPs located in the specified country (could be both source and destination)
    ips_in_country_source = df[df['source_country'].str.lower() == country_name.lower()]
    ips_in_country_destination = df[df['destination_country'].str.lower() == country_name.lower()]

    # Concatenate the source and destination IPs that match the country
    unique_ips = pd.concat([ips_in_country_source['source_ip'], ips_in_country_destination['destination_ip']])

    # Remove duplicates to keep only unique IPs
    unique_ips = unique_ips.drop_duplicates()

    # Return the unique IPs
    return unique_ips

def locate_full_ip(ip, db_path="GeoLite2-City.mmdb"):
    """
    Locates an IP and returns full details of its location (country, city, latitude, longitude).
    If the IP is private, returns a message indicating that it is private and cannot be located.
    :param ip: The IP to locate.
    :param db_path: Path to the GeoIP database.
    :return: Dictionary with the location or error message.
    """
    if is_private_ip(ip):
        return {"message": "The IP is private and cannot be located."}
    
    # Locate the IP using the GeoIP database
    geo_info = geo_locate_ip(ip, db_path)
    
    if geo_info:
        return geo_info  # Return the location details if found
    else:
        return {"message": "Could not locate the IP."}

def geolocate_unique_ips(df, db_path="GeoLite2-City.mmdb"):
    """
    Geolocates all unique public IPs found in the DataFrame (both source and destination).
    Filters out private and unlocatable IPs.
    
    :param df: DataFrame with normalized data.
    :param db_path: Path to the GeoIP database.
    :return: Dictionary of IP -> geolocation info (excluding None results).
    """
    ips = set(df['source_ip'].dropna().unique()).union(df['destination_ip'].dropna().unique())
    results = {}
    
    for ip in ips:
        if not is_private_ip(ip):
            geo = geo_locate_ip(ip, db_path)
            if geo is not None:
                results[ip] = geo
                
    return results

def generate_timeline(df, date_range):
    """
    Generates the traffic evolution over time based on the provided date range.
    :param df: DataFrame containing the network traffic data.
    :param date_range: A date or date range (in 'YYYY-MM-DD' or 'YYYY-MM-DD:YYYY-MM-DD' format).
    :return: The traffic evolution (packet count per minute) for the specified date range.
    """
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    if date_range:
        try:
            # Check if it's a range of dates (start:end)
            if ':' in date_range:
                start_date, end_date = date_range.split(':')
                start_date = pd.to_datetime(start_date).date()
                end_date = pd.to_datetime(end_date).date()
                df_filtered = df[(df['timestamp'].dt.date >= start_date) & (df['timestamp'].dt.date <= end_date)]
                if df_filtered.empty:
                    return f"No packets found between {start_date} and {end_date}."
                return df_filtered.set_index('timestamp').resample('1Min').size().to_string(index=True)
            else:
                target_date = pd.to_datetime(date_range).date()
                df_filtered = df[df['timestamp'].dt.date == target_date]
                if df_filtered.empty:
                    return f"No packets found on {target_date}."
                return df_filtered.set_index('timestamp').resample('1Min').size().to_string(index=True)
        except Exception:
            return "Invalid date format. Use the format YYYY-MM-DD or YYYY-MM-DD:YYYY-MM-DD"
    else:
        print("No date range provided, showing the complete timeline.")
        timeline = df.set_index('timestamp').resample('1Min').size()
    
        if len(timeline) > 10:
            timeline.to_csv('timeline.csv')
            print(f"Timeline has been exported to 'timeline.csv' because it exceeds 10 entries.")
        
        return timeline.head(10).to_string(index=True)

def list_ips(df):
    """
    Lists all unique source and destination IPs in the given DataFrame.
    :param df: DataFrame containing the network traffic data.
    :return: String displaying the list of unique source and destination IPs.
    """
    sources = df['source_ip'].dropna().unique()
    destinations = df['destination_ip'].dropna().unique()

    # Prepare result string
    result = f"\nSource IPs: {sources}\n"
    result += f"\nDestination IPs: {destinations}"

    return result

def list_protocols(df):
    """
    Lists the detected protocols in the given DataFrame.
    :param df: DataFrame containing the network traffic data.
    :return: String displaying the count of each protocol detected.
    """
    protocols = df['protocol'].value_counts()

    if protocols.empty:
        return "\nNo protocols detected."

    # Return the protocols as a formatted string
    return f"\nDetected protocols:\n{protocols.to_string()}"

def list_sessions(df):
    """
    Lists the most frequent sessions (source IP, destination IP, source port, destination port).
    :param df: DataFrame containing the network traffic data.
    :return: String displaying the top 20 most frequent sessions.
    """
    sessions = df.groupby(['source_ip', 'destination_ip', 'source_port', 'destination_port']).size() \
                .reset_index(name='count') \
                .sort_values(by='count', ascending=False) \
                .head(20)

    # Return the top 20 most frequent sessions as a formatted string
    return f"\nMost frequent sessions:\n{sessions.to_string(index=False)}"

def list_top_macs(df):
    """
    Lists the top 10 source and destination MAC addresses.
    :param df: DataFrame containing the network traffic data.
    :return: String displaying the top 10 source and destination MAC addresses.
    """
    sources = df['source_mac'].value_counts().head(10)
    destinations = df['destination_mac'].value_counts().head(10)

    # Return the top 10 source and destination MACs as a formatted string
    result = f"Top 10 source MACs:\n{sources.to_string(index=False)}\n"
    result += f"\nTop 10 destination MACs:\n{destinations.to_string(index=False)}"
    return result

def compare_pcap_files(df1, file1_path, file2_path):
    """
    Compares two .pcap files and outputs differences in IPs and protocols.
    :param df1: DataFrame of the first .pcap file.
    :param file1_path: Path to the first .pcap file.
    :param file2_path: Path to the second .pcap file.
    :return: String displaying the comparison results.
    """
    if not os.path.exists(file2_path):
        return f"File not found: {file2_path}"

    # Load the second pcap file's DataFrame
    df2 = get_df(file2_path)

    # Extract unique IPs from both files
    ips1 = set(df1['source_ip'].dropna().unique()) | set(df1['destination_ip'].dropna().unique())
    ips2 = set(df2['source_ip'].dropna().unique()) | set(df2['destination_ip'].dropna().unique())

    # Determine new and removed IPs
    new_ips = ips2 - ips1
    removed_ips = ips1 - ips2

    # Extract unique protocols from both files
    prot1 = set(df1['protocol'].dropna().unique())
    prot2 = set(df2['protocol'].dropna().unique())

    # Determine new and removed protocols
    new_prot = prot2 - prot1
    removed_prot = prot1 - prot2

    # Prepare the comparison result string
    result = f"New IPs in {file2_path}: {new_ips if new_ips else 'None'}\n"
    result += f"\nIPs that are no longer there: {removed_ips if removed_ips else 'None'}\n"
    result += f"\nNew protocols: {new_prot if new_prot else 'None'}\n"
    result += f"\nRemoved protocols: {removed_prot if removed_prot else 'None'}"

    # Include packet count for both files
    result += f"\n\nTotal packets:"
    result += f"\n  {file1_path}: {len(df1)} packets"
    result += f"\n  {file2_path}: {len(df2)} packets"

    return result

def list_ports(df):
    """
    Lists the most used source and destination ports in the given DataFrame.
    :param df: DataFrame containing the network traffic data.
    :return: String displaying the most used source and destination ports.
    """
    # Get the most used source and destination ports (top 20)
    source_ports = df['source_port'].value_counts().head(20)
    destination_ports = df['destination_port'].value_counts().head(20)

    # Remove any NaN values from the source and destination ports
    source_ports = source_ports.dropna()
    destination_ports = destination_ports.dropna()

    # If source ports have more than 20 entries, export them to CSV
    if len(source_ports) > 20:
        source_ports.to_csv('source_ports.csv', header=True)
        print("Source ports table has been exported to 'source_ports.csv' because it exceeds 20 entries.")

    # If destination ports have more than 20 entries, export them to CSV
    if len(destination_ports) > 20:
        destination_ports.to_csv('destination_ports.csv', header=True)
        print("Destination ports table has been exported to 'destination_ports.csv' because it exceeds 20 entries.")

    # Return the top 20 source and destination ports as formatted strings
    result = f"Source Ports:\n{source_ports.to_string()}"
    result += f"\n\nDestination Ports:\n{destination_ports.to_string()}"
    
    return result

def main():
    parser = argparse.ArgumentParser(description="PCAP traffic analyzer for anomaly detection.")
    parser.add_argument("pcap_path", help="Path to the .pcap file to analyze")
    parser.add_argument("action", choices=[
        "syn", "fin", "xmas", "null", "ddos", "dns", "icmp", "http", "lat-movement",
        "find-ip", "find-ip-country", "stats", "geo-ips", "list-ips", 
        "protocols", "sessions", "timeline", "top-macs",
        "compare", "domains", "access-domain",
        "list-ports", "ip-count", "session-detail", "dns-to-ip", "loc-ip"
    ], help="Type of analysis to perform or action to execute")
    parser.add_argument("value", nargs="?", help="Additional value")

    args = parser.parse_args()

    if not os.path.exists(args.pcap_path):
        print("File not found.")
        sys.exit(1)

    print(f"Analyzing file: {args.pcap_path}")
    print(f"This may take a few minutes...")
    df = None

    if args.action == "syn":
        results = detect_scan(args.pcap_path, "tcp.flags.syn==1 && tcp.flags.ack==0")
        print("Possible SYN Scan detected:")
        print(results)

    if args.action == "fin":
        results = detect_scan(args.pcap_path, "tcp.flags.fin==1 && tcp.flags.syn==0 && tcp.flags.ack==0")
        print("Possible FIN Scan detected:")
        print(results)

    if args.action == "xmas":
        results = detect_scan(args.pcap_path, "tcp.flags.fin==1 && tcp.flags.push==1 && tcp.flags.urg==1 && tcp.flags.syn==0")
        print("Possible Xmas Scan detected:")
        print(results)

    elif args.action == "null":
        results = detect_scan(args.pcap_path, "tcp.flags==0")
        print("Possible null Scan detected:")
        print(results)

    elif args.action == "ddos":
        sources, destinations = detect_ddos(args.pcap_path)
        print("\nPotential source IPs for DDoS:", sources)
        print("\nPotential destination IPs for DDoS:", destinations)

    elif args.action == "dns":
        results = analyze_dns(args.pcap_path)

    elif args.action == "icmp":
        results = analyze_icmp(args.pcap_path)

    elif args.action == "http":
        results = analyze_http(args.pcap_path)

    elif args.action == "lat-movement":
        df = get_df(args.pcap_path)
        results = detect_lateral_movement(df)

    elif args.action == "find-ip":
        df = get_df(args.pcap_path)
        if args.value:
            results = find_ip(df, args.value)
            print(f"Matches for IP {args.value}:")
            print(results)
        else:
            print("No IP provided. Please specify an IP to analyze.")

    elif args.action == "find-ip-country":
        df = get_df(args.pcap_path)
        if args.value:
            results = find_ip_country(df, args.value)
            print(f"\nIPs located in {args.value}:")
            print(results.to_string())
        else:
            print("No country code provided. Showing general traffic statistics:")
            stats = get_traffic_statistics(df)
            stats

    elif args.action == "stats":
        print("\nTraffic statistics:")
        df = get_df(args.pcap_path)
        generate_statistics(df)
        advanced_statistics(df)

    elif args.action == "geo-ips":
        df = get_df(args.pcap_path)
        print("\nGeolocating unique IPs...")
        geo_results = geolocate_unique_ips(df)
        for ip, geo in geo_results.items():
            print(f"{ip}: {geo}")

    elif args.action == "list-ips":
        df = get_df(args.pcap_path)
        results = list_ips(df)
        print(f"{results}")

    elif args.action == "protocols":
        df = get_df(args.pcap_path)
        results = list_protocols(df)
        print(f"\n{results}")

    elif args.action == "sessions":
        df = get_df(args.pcap_path)
        results = list_sessions(df)
        print(f"{results}")

    elif args.action == "timeline":
        df = get_df(args.pcap_path)
        results = generate_timeline(df, args.value)
        print(f"\nTrafic evolution:\n{results}")

    elif args.action == "top-macs":
        df = get_df(args.pcap_path)
        results = list_top_macs(df)
        print(f"\n{results}")

    elif args.action == "compare":
        df1 = get_df(args.pcap_path)
        print(f"\nComparing: {args.pcap_path} vs {args.value}\n")
        results = compare_pcap_files(df1, args.pcap_path, args.value)
        print(f"\n{results}")

    elif args.action == "domains":
        domains = extract_dns_domains(args.pcap_path)
        print(f"\n{len(domains)} domains extracted:")
        for d in domains:
            print(d)

    elif args.action == "list-ports":
        df = get_df(args.pcap_path)
        results = list_ports(df)
        print(f"\n{results}")

    elif args.action == "ip-count":
        df = get_df(args.pcap_path)
        count = count_packets_by_ip(df)
        print("\nPackets by IP (source + destination):")
        print(count)

    elif args.action == "session-detail":
        if not args.value or ',' not in args.value:
            print("\nSpecify two IPs separated by comma. E.g., 192.168.1.1,10.0.0.2")
        else:
            ip1, ip2 = args.value.split(',')
            df = get_df(args.pcap_path)
            result = session_detail(df, ip1.strip(), ip2.strip())
            print(f"\nSession between {ip1} and {ip2}:")
            print(result[['timestamp', 'protocol', 'source_port', 'destination_port']])

    elif args.action == "dns-to-ip":
        if not args.value:
            print("\nYou must specify a domain.")
        else:
            results = resolve_dns_domain(args.pcap_path, args.value)
            print(f"\nResolved IPs for {args.value}: {results if results else 'None found'}")

    elif args.action == "access-domain":
        if not args.value:
            print("\nYou must specify a domain.")
        else:
            results = access_domain(args.pcap_path, args.value)
            print(f"\nIPs that accessed {args.value}: {results if results else 'None found'}")

    elif args.action == "loc-ip":
        if not args.value:
            print("\nYou must specify a IP.")
        else:
            result = locate_full_ip(args.value)
            print('\n',result)

if __name__ == "__main__":
    main()