#!/usr/bin/env python3
import sqlite3
import os
import argparse
import matplotlib.pyplot as plt

parser = argparse.ArgumentParser(description="Plot time-series CPU and RAM usage from SQLite database.")
parser.add_argument(
    "-d", "--db-path",
    default="experiment_results/resource_stats.db",
    help="Path to SQLite database file (default: experiment_results/resource_stats.db)",
)
parser.add_argument(
    "-o", "--output-image",
    default="experiment_results/experiment_plot.png",
    help="Path to output plot PNG file (default: experiment_results/experiment_plot.png)",
)
args = parser.parse_args()
db_path = args.db_path
output_image = args.output_image

if not os.path.exists(db_path):
    print(f"Could not find database at {db_path}. Have you run the experiment?")
    exit(1)


out_dir = os.path.dirname(output_image)
if out_dir:
    os.makedirs(out_dir, exist_ok=True)


# 1. Get aggregated time-series data from SQLite (grouped by timestamp)
print("Reading time-series data from SQLite...")
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Aggregate totals across all containers running at each timestamp
cursor.execute("""
    SELECT timestamp, SUM(cpu_perc) as total_cpu, AVG(mem_perc) as avg_mem
    FROM stats
    GROUP BY timestamp
    ORDER BY MIN(id) ASC
""")
rows = cursor.fetchall()
conn.close()

if not rows:
    print("Database is empty. No time-series data to plot.")
    exit(0)

from datetime import datetime

# Extract columns and compute elapsed seconds from the first measurement (t=0)
raw_timestamps = [row[0] for row in rows]
cpu_data = [row[1] for row in rows]
mem_data = [row[2] for row in rows]

# Parse HH:MM:SS timestamps into elapsed seconds
def parse_time_to_seconds(ts_str):
    try:
        t = datetime.strptime(ts_str.strip(), "%H:%M:%S")
        return t.hour * 3600 + t.minute * 60 + t.second
    except Exception:
        return 0

base_sec = parse_time_to_seconds(raw_timestamps[0])
elapsed_seconds = []
for ts in raw_timestamps:
    sec = parse_time_to_seconds(ts)
    diff = sec - base_sec
    if diff < 0:  # Handle midnight rollover if necessary
        diff += 86400
    elapsed_seconds.append(diff)

# Generate evenly spaced ticks (between 5 and 10 labels) based on elapsed seconds
n_points = len(elapsed_seconds)
num_ticks = min(10, n_points)
if num_ticks > 1:
    step = (n_points - 1) / (num_ticks - 1)
    display_indices = [int(round(i * step)) for i in range(num_ticks)]
    display_indices = sorted(list(set(display_indices)))
else:
    display_indices = [0]

display_ticks = [elapsed_seconds[i] for i in display_indices]
display_labels = [f"{elapsed_seconds[i]}s" for i in display_indices]

# 2. Generate the plot (Two graphs in one image, with shared X-axis)
fig, ax1 = plt.subplots(figsize=(10, 5))

# Plot CPU (Left Y-axis)
color = 'tab:blue'
ax1.set_xlabel('Elapsed Time (seconds)', fontweight='bold', labelpad=10)
ax1.set_ylabel('Total CPU Usage (%)', color=color, fontweight='bold')
ax1.plot(elapsed_seconds, cpu_data, color=color, linewidth=2, label='Total CPU %')
# Dynamic scaling for Y-axes with padding so small usage isn't pinned to the bottom floor
max_cpu = max(cpu_data) if cpu_data else 1.0
min_cpu = min(cpu_data) if cpu_data else 0.0
cpu_headroom = max(0.5, (max_cpu - min_cpu) * 0.15)
ax1.set_ylim(max(0, min_cpu - cpu_headroom * 0.5), max_cpu + cpu_headroom)

ax1.set_xticks(display_ticks)
ax1.set_xticklabels(display_labels, rotation=45)

# Plot RAM (Right Y-axis)
ax2 = ax1.twinx()  
color = 'tab:orange'
ax2.set_ylabel('Average RAM Usage (%)', color=color, fontweight='bold')
ax2.plot(elapsed_seconds, mem_data, color=color, linewidth=2, linestyle='--', label='Avg RAM %')
ax2.tick_params(axis='y', labelcolor=color)

max_mem = max(mem_data) if mem_data else 1.0
min_mem = min(mem_data) if mem_data else 0.0
mem_headroom = max(0.1, (max_mem - min_mem) * 0.15)
ax2.set_ylim(max(0, min_mem - mem_headroom * 0.5), max_mem + mem_headroom)

# Title and layout
plt.title('Experiment: Resource Allocation over time', fontsize=14, fontweight='bold', pad=15)
fig.tight_layout()

# Save file
plt.savefig(output_image, dpi=150)
print(f"Success! The graph has been saved as an image here: {output_image}")