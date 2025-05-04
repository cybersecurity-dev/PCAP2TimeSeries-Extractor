import csv
import os
import ipaddress
import argparse
from collections import defaultdict

import networkx as nx
import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP

def is_private_ip(ip):
    """Check if an IP address is a private (local) IP."""
    try:
        ip_addr = ipaddress.ip_address(ip)
        return (ip_addr.is_private or
                ip_addr in ipaddress.ip_network('169.254.0.0/16'))  # APIPA range
    except ValueError:
        return False

def should_include_pair(src_ip, dst_ip, packet_filter):
    """Determine if an IP pair should be included based on the packet filter."""
    src_is_private = is_private_ip(src_ip)
    dst_is_private = is_private_ip(dst_ip)
    
    if packet_filter == "internal":
        return src_is_private and dst_is_private
    elif packet_filter == "external":
        return not src_is_private or not dst_is_private
    else:  # "all"
        return True

def process_pcap(pcap_file, packet_filter="all", output_dir = "ip_pair_csvs", summary_csv = "ip_to_ip_pairs.csv", graph_output = "ip_communication_graph.svg"):
    # Validate packet_filter
    valid_filters = ["internal", "external", "all"]
    if packet_filter not in valid_filters:
        raise ValueError(f"Invalid packet_filter value. Must be one of {valid_filters}")
    
    packets = rdpcap(pcap_file)
    
    # Dictionary to store IP pair communications for individual CSVs
    ip_pairs = defaultdict(list)
    
    # Dictionary to store edge weights for the graph and summary CSV (packet counts and bytes)
    edge_weights = defaultdict(lambda: {'packets': 0, 'bytes': 0})
    
    # Process each packet
    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            timestamp = pkt.time
            packet_size = len(pkt)
            
            # Create a tuple for the IP pair (sorted for individual CSVs)
            ip_pair = tuple(sorted([src_ip, dst_ip]))
            
            # Increment edge weight for the directed edge (src_ip -> dst_ip) for summary
            edge_weights[(src_ip, dst_ip)]['packets'] += 1
            edge_weights[(src_ip, dst_ip)]['bytes'] += packet_size
            
            # Check if this pair should be included in individual CSVs based on the filter
            if should_include_pair(src_ip, dst_ip, packet_filter):
                # Determine direction relative to the first IP in the pair for individual CSVs
                is_incoming = src_ip != ip_pair[0]
                is_outgoing = src_ip == ip_pair[0]
                
                ip_pairs[ip_pair].append({
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'is_incoming_packet': is_incoming,
                    'incoming_packet_size': packet_size if is_incoming else 0,
                    'is_outgoing_packet': is_outgoing,
                    'outgoing_packet_size': packet_size if is_outgoing else 0
                })
    
    # Create a directory to store individual CSV files
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Write individual CSV files for each IP pair (filtered)
    for ip_pair, communications in ip_pairs.items():
        ip1, ip2 = ip_pair
        filename = f"{output_dir}/{ip1}_to_{ip2}.csv"
        
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = [
                'timestamp', 
                'src_ip', 
                'dst_ip', 
                'is_incoming_packet', 
                'incoming_packet_size', 
                'is_outgoing_packet', 
                'outgoing_packet_size'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for comm in communications:
                writer.writerow({
                    'timestamp': comm['timestamp'],
                    'src_ip': comm['src_ip'],
                    'dst_ip': comm['dst_ip'],
                    'is_incoming_packet': comm['is_incoming_packet'],
                    'incoming_packet_size': comm['incoming_packet_size'],
                    'is_outgoing_packet': comm['is_outgoing_packet'],
                    'outgoing_packet_size': comm['outgoing_packet_size']
                })
    
    print(f"Individual CSV files have been generated in the '{output_dir}' directory (filter: {packet_filter}).")
    
    # Write a summary CSV for all IP-to-IP pairs (unfiltered)
    with open(summary_csv, 'w', newline='') as csvfile:
        fieldnames = ['src_ip', 'dst_ip', 'total_packets', 'total_bytes', 'src_ip_is_local_ip', 'dst_ip_is_local_ip']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for (src_ip, dst_ip), data in edge_weights.items():
            writer.writerow({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'total_packets': data['packets'],
                'total_bytes': data['bytes'],
                'src_ip_is_local_ip': is_private_ip(src_ip),
                'dst_ip_is_local_ip': is_private_ip(dst_ip)
            })
    
    print(f"Summary of all IP-to-IP communication pairs has been saved as '{summary_csv}'.")
    
    # Create and save the IP communication graph (filtered)
    G = nx.DiGraph()
    
    # Add edges with weights for the graph, but only for pairs that match the filter
    for (src_ip, dst_ip), data in edge_weights.items():
        if should_include_pair(src_ip, dst_ip, packet_filter):
            G.add_edge(src_ip, dst_ip, weight=data['packets'])
    
    # Set up the plot
    plt.figure(figsize=(15, 12))
    pos = nx.spring_layout(G, k=1.5, iterations=50)
    
    # Draw nodes
    nx.draw_networkx_nodes(G, pos, node_color='lightblue', node_size=400, alpha=0.8)
    
    # Draw edges with lighter color and varying thickness based on weight
    if G.edges(data=True):  # Check if there are edges to avoid division by zero
        edge_widths = [0.5 + 2 * (d['weight'] / max([d['weight'] for _, _, d in G.edges(data=True)])) for _, _, d in G.edges(data=True)]
    else:
        edge_widths = []
    nx.draw_networkx_edges(G, pos, edge_color='gray', width=edge_widths, arrows=True, arrowsize=15)
    
    # Draw node labels with background
    node_labels = {node: node for node in G.nodes()}
    for node, (x, y) in pos.items():
        plt.text(x, y, node, fontsize=8, ha='center', va='center', bbox=dict(facecolor='white', alpha=0.7, edgecolor='none', boxstyle='round,pad=0.3'))
    
    # Draw edge labels (packet counts)
    edge_labels = {(u, v): f"{d['weight']}" for u, v, d in G.edges(data=True)}
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=6, label_pos=0.5, alpha=0.8)
    
    # Adjust plot settings
    plt.title(f"IP Communication Graph (Filter: {packet_filter})", fontsize=12, pad=20)
    plt.axis('off')
    
    # Save the graph as SVG
    plt.savefig(graph_output, format='svg', bbox_inches='tight', dpi=300)
    plt.close()
    
    print(f"IP communication graph has been saved as '{graph_output}' (filter: {packet_filter}).")


# python3 extract_ip2ip_packet_size.py -packet_filter external <pcap file path>
if __name__ == "__main__":
    
    # Set up argument parser for command-line arguments
    parser = argparse.ArgumentParser(description="Extract IP-to-IP communication from a PCAP file.")
    parser.add_argument("pcap_file", help="Path to the PCAP file")
    parser.add_argument("-packet_filter", choices=["internal", "external", "all"], default="all",
                        help="Filter for individual CSV files and graph: 'internal' (both IPs private), 'external' (at least one IP public), 'all' (no filter)")
    
    args = parser.parse_args()
    
    # Process the PCAP file with the specified filter
    process_pcap(args.pcap_file, args.packet_filter)