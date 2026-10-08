#!/usr/bin/env python3
import sqlite3
import os
import argparse
import matplotlib.pyplot as plt
from datetime import datetime

parser = argparse.ArgumentParser(description="Plot network telemetry metrics (Ping RTT & Gossip Bytes) from SQLite.")
parser.add_argument(
    "-d", "--db-path",
    default="experiment_results/network_telemetry.db",
    help="Path to SQLite telemetry DB (default: experiment_results/network_telemetry.db)",
)
parser.add_argument(
    "-o", "--output-image",
    default="experiment_results/network_telemetry.png",
    help="Path to output plot PNG (default: experiment_results/network_telemetry.png)",
)
args = parser.parse_args()
db_path = args.db_path
output_image = args.output_image

if not os.path.exists(db_path):
    print(f"Could not find telemetry database at {db_path}.")
    exit(1)

out_dir = os.path.dirname(output_image)
if out_dir:
    os.makedirs(out_dir, exist_ok=True)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Query matched RTTs
cursor.execute("""
    SELECT timestamp, rtt_ms FROM ping_pong_events 
    WHERE event_type = 'PONG' AND rtt_ms IS NOT NULL 
    ORDER BY id ASC
""")
rtt_rows = cursor.fetchall()

# Query TCP gossip byte throughput grouped by second
cursor.execute("""
    SELECT timestamp, SUM(packet_bytes) as total_bytes 
    FROM tcp_traffic_stats 
    GROUP BY timestamp 
    ORDER BY MIN(id) ASC
""")
tcp_rows = cursor.fetchall()
conn.close()

if not rtt_rows and not tcp_rows:
    print("No telemetry data to plot.")
    exit(0)

fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8), sharex=False)

# 1. Plot Ping RTTs
if rtt_rows:
    rtt_vals = [row[1] for row in rtt_rows]
    ax1.plot(range(len(rtt_vals)), rtt_vals, color='tab:blue', marker='.', linestyle='none', label='Ping RTT (ms)')
    ax1.set_ylabel('RTT (ms)', fontweight='bold', color='tab:blue')
    ax1.set_title('Failure Detection: Ping/Pong Round-Trip Time', fontweight='bold')
    ax1.grid(True, linestyle='--', alpha=0.5)
else:
    ax1.text(0.5, 0.5, 'No Pong RTT events recorded', ha='center', va='center')

# 2. Plot TCP Gossip Wire Bytes
if tcp_rows:
    bytes_vals = [row[1] / 1024.0 for row in tcp_rows] # KB
    ax2.plot(range(len(bytes_vals)), bytes_vals, color='tab:purple', linewidth=2, label='Gossip KB/s')
    ax2.set_xlabel('Elapsed Measurement Window', fontweight='bold')
    ax2.set_ylabel('Throughput (KB/s)', fontweight='bold', color='tab:purple')
    ax2.set_title('Gossip Protocol Wire Bandwidth', fontweight='bold')
    ax2.grid(True, linestyle='--', alpha=0.5)
else:
    ax2.text(0.5, 0.5, 'No TCP Gossip traffic recorded', ha='center', va='center')

fig.tight_layout()
plt.savefig(output_image, dpi=150)
print(f"Network telemetry plot saved to: {output_image}")
