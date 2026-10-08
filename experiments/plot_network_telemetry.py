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

def parse_time_to_seconds(ts_str):
    try:
        ts_clean = ts_str.strip()
        if "." in ts_clean:
            t = datetime.strptime(ts_clean, "%H:%M:%S.%f")
            return t.hour * 3600 + t.minute * 60 + t.second + t.microsecond / 1e6
        else:
            t = datetime.strptime(ts_clean, "%H:%M:%S")
            return float(t.hour * 3600 + t.minute * 60 + t.second)
    except Exception:
        return 0.0

# Determine global base timestamp and wall-clock start time
def parse_time_obj(ts_str):
    ts_clean = ts_str.strip()
    if "." in ts_clean:
        return datetime.strptime(ts_clean, "%H:%M:%S.%f")
    return datetime.strptime(ts_clean, "%H:%M:%S")

all_raw_ts = [row[0] for row in rtt_rows] + [row[0] for row in tcp_rows]
all_dt = [parse_time_obj(ts) for ts in all_raw_ts]
start_dt = min(all_dt) if all_dt else datetime.now()

def to_elapsed_sec(dt):
    delta = (dt - start_dt).total_seconds()
    if delta < 0:
        delta += 86400.0
    return delta

fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(11, 8.5), sharex=True)

# 1. Plot Ping RTTs over elapsed time
if rtt_rows:
    rtt_times = [to_elapsed_sec(parse_time_obj(row[0])) for row in rtt_rows]
    rtt_vals = [row[1] for row in rtt_rows]

    ax1.scatter(rtt_times, rtt_vals, color='tab:blue', s=24, alpha=0.85, edgecolors='none', label='Observed Ping RTT')
    
    # Statistical reference lines
    avg_rtt = sum(rtt_vals) / len(rtt_vals)
    ax1.axhline(avg_rtt, color='darkorange', linestyle='--', linewidth=1.5, label=f'Mean RTT: {avg_rtt:.2f} ms')
    
    ax1.set_ylabel('Round-Trip Time (ms)', fontweight='bold', color='tab:blue')
    ax1.set_title(f'Failure Detection: Ping/Pong RTT ({len(rtt_vals)} samples, Mean: {avg_rtt:.2f} ms)', fontweight='bold')
    ax1.grid(True, linestyle='--', alpha=0.5)
    ax1.legend(loc='upper right', framealpha=0.9)
else:
    ax1.text(0.5, 0.5, 'No Pong RTT events recorded', ha='center', va='center', fontsize=12)

# 2. Plot TCP Gossip Wire Bytes over elapsed time
if tcp_rows:
    tcp_times = [to_elapsed_sec(parse_time_obj(row[0])) for row in tcp_rows]
    bytes_vals = [row[1] / 1024.0 for row in tcp_rows] # KB/s

    ax2.plot(tcp_times, bytes_vals, color='tab:purple', marker='o', markersize=4, linewidth=1.8, label='Wire Throughput (KB/s)')
    ax2.fill_between(tcp_times, bytes_vals, color='tab:purple', alpha=0.15)
    
    total_kb = sum(row[1] for row in tcp_rows) / 1024.0
    ax2.set_ylabel('Throughput (KB/s)', fontweight='bold', color='tab:purple')
    ax2.set_title(f'Gossip Protocol Wire Bandwidth (Total: {total_kb:.1f} KB transferred)', fontweight='bold')
    ax2.grid(True, linestyle='--', alpha=0.5)
    ax2.legend(loc='upper right', framealpha=0.9)
else:
    ax2.text(0.5, 0.5, 'No TCP Gossip traffic recorded', ha='center', va='center', fontsize=12)

# Informative shared X-axis with both elapsed seconds and wall-clock timestamp
start_time_str = start_dt.strftime("%H:%M:%S")
ax2.set_xlabel(f'Elapsed Time from Start (seconds)  [Experiment start: {start_time_str}]', fontweight='bold', labelpad=8)

# Format ticks cleanly
max_time = max([to_elapsed_sec(dt) for dt in all_dt]) if all_dt else 1.0
ax2.set_xlim(-0.5, max_time + 1.0)

fig.tight_layout()
plt.savefig(output_image, dpi=150)
print(f"Network telemetry plot saved to: {output_image}")
