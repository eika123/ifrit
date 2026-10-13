#!/usr/bin/env python3
"""
merge_gossip_telemetry.py

Dynamically extracts schema and column definitions directly from source SQLite 
telemetry databases and merges them into a unified database. Any later schema extensions
are automatically recognized without modifying this script.
"""

import argparse
import glob
import os
import sqlite3
import sys

def get_table_schema_and_columns(src_cursor, table_name="gossip_exchange"):
    """Extracts CREATE TABLE SQL and column names from the source database."""
    src_cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?;", (table_name,))
    row = src_cursor.fetchone()
    if not row or not row[0]:
        return None, []

    create_table_sql = row[0]

    # Get column names dynamically via PRAGMA table_info
    src_cursor.execute(f"PRAGMA table_info({table_name});")
    columns = [col[1] for col in src_cursor.fetchall()]

    return create_table_sql, columns

def load_docker_dns(dns_file_path):
    """Parses docker inspect output file (format: `<ip> /<container_name>`) and returns {ip: name}."""
    mapping = {}
    if not dns_file_path or not os.path.isfile(dns_file_path):
        return mapping

    try:
        with open(dns_file_path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    raw_name = parts[1].strip().lstrip("/")
                    # Clean docker compose prefix like 'ifrit-gossip-node-1' -> 'gossip-node-1'
                    name = raw_name
                    if name.startswith("ifrit-"):
                        name = name[len("ifrit-"):]
                    if ip and name:
                        mapping[ip] = name
    except Exception as e:
        print(f"Warning: Failed reading DNS file {dns_file_path}: {e}", file=sys.stderr)

    return mapping

def merge_databases(db_files, output_db, cleanup_sources=False, dns_file=None):
    if not db_files and not dns_file:
        print("No telemetry databases found to merge.")
        return 0

    out_dir = os.path.dirname(output_db)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    dest_conn = sqlite3.connect(output_db)
    dest_cursor = dest_conn.cursor()

    schema_initialized = False
    columns = []
    total_rows = 0
    merged_sources = []

    dest_cursor.execute("PRAGMA busy_timeout = 5000;")

    # 1. First populate node_identity from docker_dns file if provided
    dns_mapping = load_docker_dns(dns_file)
    if dns_mapping:
        dest_cursor.execute("CREATE TABLE IF NOT EXISTS node_identity (ip TEXT PRIMARY KEY, name TEXT);")
        dest_cursor.executemany(
            "INSERT OR REPLACE INTO node_identity (ip, name) VALUES (?, ?);",
            list(dns_mapping.items())
        )
        dest_conn.commit()
        print(f"Loaded {len(dns_mapping)} node identities from {dns_file}")

    for db_path in db_files:
        if not os.path.isfile(db_path) or os.path.getsize(db_path) == 0:
            continue

        try:
            src_conn = sqlite3.connect(db_path)
            src_cursor = src_conn.cursor()

            # Dynamically extract schema from the first valid source database
            if not schema_initialized:
                create_sql, cols = get_table_schema_and_columns(src_cursor, "gossip_exchange")
                if create_sql and cols:
                    dest_cursor.executescript(create_sql + ";")
                    # Build standard indices if present in schema
                    if "timestamp" in cols:
                        dest_cursor.execute("CREATE INDEX IF NOT EXISTS idx_gossip_ts ON gossip_exchange(timestamp);")
                    if "host" in cols:
                        dest_cursor.execute("CREATE INDEX IF NOT EXISTS idx_gossip_host ON gossip_exchange(host);")
                    if "direction" in cols:
                        dest_cursor.execute("CREATE INDEX IF NOT EXISTS idx_gossip_dir ON gossip_exchange(direction);")

                    dest_conn.commit()
                    columns = cols
                    schema_initialized = True

            if not schema_initialized:
                src_conn.close()
                continue

            # Dynamically select all columns discovered in the schema
            col_list_str = ", ".join(columns)
            placeholders = ", ".join(["?"] * len(columns))
            query = f"SELECT {col_list_str} FROM gossip_exchange;"

            src_cursor.execute(query)
            rows = src_cursor.fetchall()

            # Merge node_identity entries if present in source (only if not already registered)
            try:
                src_cursor.execute("SELECT ip, name FROM node_identity;")
                identities = src_cursor.fetchall()
                if identities:
                    dest_cursor.execute("CREATE TABLE IF NOT EXISTS node_identity (ip TEXT PRIMARY KEY, name TEXT);")
                    dest_cursor.executemany("INSERT OR IGNORE INTO node_identity (ip, name) VALUES (?, ?);", identities)
                    dest_conn.commit()
            except Exception:
                pass

            src_conn.close()

            # Insert dynamically into destination database
            if rows:
                insert_sql = f"INSERT INTO gossip_exchange ({col_list_str}) VALUES ({placeholders});"
                dest_cursor.executemany(insert_sql, rows)
                dest_conn.commit()
                total_rows += len(rows)
                merged_sources.append(db_path)

        except Exception as e:
            print(f"Warning: Failed reading {db_path}: {e}", file=sys.stderr)

    dest_conn.close()

    if schema_initialized:
        print(f"Successfully merged {total_rows} gossip exchange rows from {len(merged_sources)} node databases into {output_db}")
    else:
        print("Notice: No gossip_exchange tables found in source databases.")

    if cleanup_sources:
        for p in merged_sources:
            for ext in ("", "-wal", "-shm"):
                f = p + ext if ext else p
                if os.path.exists(f):
                    os.remove(f)
        print(f"Cleaned up {len(merged_sources)} individual node databases.")

    return total_rows

def main():
    parser = argparse.ArgumentParser(description="Merge per-node gossip telemetry SQLite databases into a unified database.")
    parser.add_argument("-d", "--dir", default="experiment_results", help="Directory containing telemetry_*.db files")
    parser.add_argument("-o", "--output", default="experiment_results/unified_gossip_telemetry.db", help="Output unified SQLite database path")
    parser.add_argument("--pattern", default="telemetry_*.db", help="Filename pattern to match node databases")
    parser.add_argument("--dns-file", default=None, help="Path to docker inspect DNS text file (<ip> <container_name>)")
    parser.add_argument("--cleanup", action="store_true", help="Remove source databases after successful merge")

    args = parser.parse_args()

    dns_file = args.dns_file
    if not dns_file:
        candidate_dns = os.path.join(args.dir, "docker_dns.txt")
        if os.path.isfile(candidate_dns):
            dns_file = candidate_dns

    search_pattern = os.path.join(args.dir, args.pattern)
    db_files = sorted(glob.glob(search_pattern))

    merge_databases(db_files, args.output, cleanup_sources=args.cleanup, dns_file=dns_file)

if __name__ == "__main__":
    main()
