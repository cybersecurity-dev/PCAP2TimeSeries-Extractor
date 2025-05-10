import csv
import os
import ipaddress
import argparse
from collections import defaultdict

from scapy.all import rdpcap, IP
import networkx as nx
import matplotlib.pyplot as plt

import dash
from dash import dcc, html
import plotly.graph_objects as go

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

def create_plotly_dash_graph(G, pos, packet_filter):
    """Create an interactive Plotly Dash graph from a NetworkX graph."""
    # Extract node positions
    node_x = [pos[node][0] for node in G.nodes()]
    node_y = [pos[node][1] for node in G.nodes()]
    node_text = [node for node in G.nodes()]
    
    # Create node trace
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        text=node_text,
        textposition='top center',
        hoverinfo='text',
        marker=dict(
            size=15,
            color='lightblue',
            line=dict(width=2, color='black')
        )
    )
    
    # Extract edge positions
    edge_x = []
    edge_y = []
    edge_text = []
    for edge in G.edges(data=True):
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
        edge_text.append(f"Packets: {edge[2]['weight']}")
    
    # Create edge trace
    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1, color='gray'),
        hoverinfo='text',
        text=edge_text,
        mode='lines'
    )
    
    # Create the figure
    fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        title=f'IP Communication Graph (Filter: {packet_filter})',
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=20, l=5, r=5, t=40),
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                    ))
    
    # Create the Dash app
    app = dash.Dash(__name__)
    app.layout = html.Div([
        dcc.Graph(figure=fig)
    ])
    
    # Run the Dash server using the updated method
    print("Starting Plotly Dash server. Open http://127.0.0.1:8050 in your browser to view the interactive graph.")
    app.run(debug=False)

def process_pcap(pcap_file, packet_filter="all"):
    # Validate packet_filter
    valid_filters = ["internal", "external", "all"]
    if packet_filter not in valid_filters:
        raise ValueError(f"Invalid packet_filter value. Must be one of {valid_filters}")
    
    # Read the PCAP file
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
    output_dir = "ip_pair_csvs"
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
    summary_csv = "ip_to_ip_pairs.csv"
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
    
    # Create the IP communication graph (filtered)
    G = nx.DiGraph()
    
    # Add edges with weights for the graph, but only for pairs that match the filter
    for (src_ip, dst_ip), data in edge_weights.items():
        if should_include_pair(src_ip, dst_ip, packet_filter):
            G.add_edge(src_ip, dst_ip, weight=data['packets'])
    
    # Compute positions for both graphs
    pos = nx.spring_layout(G, k=1.5, iterations=50)
    
    # Generate the static SVG graph
    plt.figure(figsize=(15, 12))
    nx.draw_networkx_nodes(G, pos, node_color='lightblue', node_size=400, alpha=0.8)
    
    if G.edges(data=True):  # Check if there are edges to avoid division by zero
        edge_widths = [0.5 + 2 * (d['weight'] / max([d['weight'] for _, _, d in G.edges(data=True)])) for _, _, d in G.edges(data=True)]
    else:
        edge_widths = []
    nx.draw_networkx_edges(G, pos, edge_color='gray', width=edge_widths, arrows=True, arrowsize=15)
    
    node_labels = {node: node for node in G.nodes()}
    for node, (x, y) in pos.items():
        plt.text(x, y, node, fontsize=8, ha='center', va='center', bbox=dict(facecolor='white', alpha=0.7, edgecolor='none', boxstyle='round,pad=0.3'))
    
    edge_labels = {(u, v): f"{d['weight']}" for u, v, d in G.edges(data=True)}
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=6, label_pos=0.5, alpha=0.8)
    
    plt.title(f"IP Communication Graph (Filter: {packet_filter})", fontsize=12, pad=20)
    plt.axis('off')
    
    graph_output = "ip_communication_graph.svg"
    plt.savefig(graph_output, format='svg', bbox_inches='tight', dpi=300)
    plt.close()
    
    print(f"Static IP communication graph has been saved as '{graph_output}' (filter: {packet_filter}).")
    
    # Generate the interactive Plotly Dash graph
    if G.number_of_nodes() > 0:  # Only create the Dash app if there are nodes to display
        create_plotly_dash_graph(G, pos, packet_filter)
    else:
        print(f"No nodes to display in the Plotly Dash graph (filter: {packet_filter}).")

if __name__ == "__main__":
    # Set up argument parser for command-line arguments
    parser = argparse.ArgumentParser(description="Extract IP-to-IP communication from a PCAP file.")
    parser.add_argument("pcap_file", help="Path to the PCAP file")
    parser.add_argument("-packet_filter", choices=["internal", "external", "all"], default="all",
                        help="Filter for individual CSV files and graph: 'internal' (both IPs private), 'external' (at least one IP public), 'all' (no filter)")
    
    args = parser.parse_args()
    
    # Process the PCAP file with the specified filter
    process_pcap(args.pcap_file, args.packet_filter)