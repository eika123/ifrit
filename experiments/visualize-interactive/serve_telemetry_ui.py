"""
FastAPI Telemetry Visualizer & Explorer for Ifrit Gossip Experiments.

Focused on intuitive data exploration, node activity breakdown,
and versatile filtering across gossip exchanges.

Run with uv:
    uv run --project experiments python experiments/visualize-interactive/serve_telemetry_ui.py [db_path_or_dir] [--port 8080]
"""

import argparse
import glob
import json
import os
from typing import Any, Dict, List, Optional

import aiosqlite
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
from pydantic import BaseModel

app = FastAPI(title="Ifrit Telemetry Explorer")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

DB_TARGET = ""  # Set at startup: file or directory


def resolve_db_path() -> str:
    """Find the best database file to query."""
    candidates = []
    if DB_TARGET:
        candidates.append(DB_TARGET)

    env_target = os.environ.get("DB_TARGET") or os.environ.get("TELEMETRY_DB")
    if env_target:
        candidates.append(env_target)

    candidates.extend([
        "experiment_results",
        os.path.join("..", "experiment_results"),
        os.path.join("..", "..", "experiment_results"),
    ])

    for target in candidates:
        if os.path.isfile(target):
            return os.path.abspath(target)
        if os.path.isdir(target):
            merged = glob.glob(os.path.join(target, "gossip-telemetry_*.db"))
            if merged:
                return os.path.abspath(sorted(merged, key=os.path.getmtime, reverse=True)[0])
            node_dbs = glob.glob(os.path.join(target, "telemetry_*.db"))
            if node_dbs:
                return os.path.abspath(sorted(node_dbs, key=os.path.getmtime, reverse=True)[0])
            all_dbs = glob.glob(os.path.join(target, "*.db"))
            if all_dbs:
                return os.path.abspath(sorted(all_dbs, key=os.path.getmtime, reverse=True)[0])

    return DB_TARGET or ""


class NodeStats(BaseModel):
    host: str
    total_exchanges: int
    outgoing_count: int
    incoming_count: int
    total_data_bytes: int
    total_accusations_sent: int
    total_accusations_received: int
    active_peers_count: int
    last_seen: Optional[str] = None


class SummaryStats(BaseModel):
    total_exchanges: int = 0
    total_outgoing: int = 0
    total_incoming: int = 0
    total_accusations: int = 0
    total_rebuttals: int = 0
    unique_hosts: List[str] = []
    unique_remote_hosts: List[str] = []
    node_names: Dict[str, str] = {}
    max_notes: int = 0
    max_payload_bytes: int = 0
    total_data_bytes: int = 0
    min_timestamp: Optional[str] = None
    max_timestamp: Optional[str] = None
    nodes_summary: List[NodeStats] = []


# -------------------------------------------------------------------------
# Fetch data sets from DB 
# -------------------------------------------------------------------------
@app.get("/api/analytics")
async def get_analytics(host: Optional[str] = None, buckets: int = 50):
    target = resolve_db_path()
    exists = os.path.exists(target)
    status_info = {
        "target": target,
        "exists": exists,
        "is_dir": os.path.isdir(DB_TARGET),
        "size_bytes": os.path.getsize(target) if exists else 0,
    }

    if not exists:
        return {
            "status": status_info,
            "summary": SummaryStats().model_dump(),
            "timeline": {"labels": [], "outgoing": [], "incoming": [], "bytes": []}
        }

    async with aiosqlite.connect(f"file:{target}?mode=ro", uri=True) as db:
        # Check table
        cursor = await db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='gossip_exchange'")
        if not await cursor.fetchone():
            return {
                "status": status_info,
                "summary": SummaryStats().model_dump(),
                "timeline": {"labels": [], "outgoing": [], "incoming": [], "bytes": []}
            }

        # 1. Check table columns dynamically
        cur_cols = await db.execute("PRAGMA table_info(gossip_exchange)")
        cols = {r[1] for r in await cur_cols.fetchall()}

        data_col = "payload_data_size" if "payload_data_size" in cols else ("data_bytes" if "data_bytes" in cols else "0")
        acc_cnt_col = "COALESCE(accusation_count, 0)" if "accusation_count" in cols else "0"
        note_cnt_col = "COALESCE(note_count, 0)" if "note_count" in cols else "0"

        # Overall Metrics
        cursor_totals = await db.execute(f"""
            SELECT 
                COUNT(*),
                SUM(CASE WHEN direction = 'OUTGOING' THEN 1 ELSE 0 END),
                SUM(CASE WHEN direction = 'INCOMING' THEN 1 ELSE 0 END),
                SUM({acc_cnt_col}),
                MAX({note_cnt_col}),
                MAX(COALESCE({data_col}, 0)),
                SUM(COALESCE({data_col}, 0)),
                MIN(timestamp),
                MAX(timestamp)
            FROM gossip_exchange
        """)
        row = await cursor_totals.fetchone()

        # Check total rebuttals if rebuttal_events table exists
        total_rebuttals = 0
        try:
            cur_reb = await db.execute("SELECT COUNT(*) FROM rebuttal_events")
            r_reb = await cur_reb.fetchone()
            if r_reb and r_reb[0]:
                total_rebuttals = r_reb[0]
        except Exception:
            pass

        # Check total accusations if accusation_events table exists
        total_accs = row[3] or 0
        try:
            cur_acc = await db.execute("SELECT COUNT(*) FROM accusation_events")
            r_acc = await cur_acc.fetchone()
            if r_acc and r_acc[0]:
                total_accs = r_acc[0]
        except Exception:
            pass

        # Check total notes if note_events table exists
        max_notes = row[4] or 0
        try:
            cur_notes = await db.execute("SELECT COUNT(*) FROM note_events")
            r_notes = await cur_notes.fetchone()
            if r_notes and r_notes[0]:
                max_notes = r_notes[0]
        except Exception:
            pass

        # 2. Node Breakdown
        cursor_nodes = await db.execute(f"""
            SELECT 
                host,
                COUNT(*) as total_exchanges,
                SUM(CASE WHEN direction = 'OUTGOING' THEN 1 ELSE 0 END) as outgoing_count,
                SUM(CASE WHEN direction = 'INCOMING' THEN 1 ELSE 0 END) as incoming_count,
                SUM(COALESCE({data_col}, 0)) as total_bytes,
                SUM(CASE WHEN direction = 'INCOMING' THEN {acc_cnt_col} ELSE 0 END) as acc_sent,
                SUM(CASE WHEN direction = 'OUTGOING' THEN {acc_cnt_col} ELSE 0 END) as acc_received,
                COUNT(DISTINCT CASE WHEN direction = 'OUTGOING' THEN remote_host ELSE NULL END) as active_peers,
                MAX(timestamp) as last_seen
            FROM gossip_exchange
            WHERE host IS NOT NULL AND host != ''
            GROUP BY host
            ORDER BY total_exchanges DESC
        """)
        nodes_rows = await cursor_nodes.fetchall()
        nodes_list = [
            NodeStats(
                host=nr[0],
                total_exchanges=nr[1],
                outgoing_count=nr[2] or 0,
                incoming_count=nr[3] or 0,
                total_data_bytes=nr[4] or 0,
                total_accusations_sent=nr[5] or 0,
                total_accusations_received=nr[6] or 0,
                active_peers_count=nr[7] or 0,
                last_seen=str(nr[8]) if nr[8] else None,
            ).model_dump()
            for nr in nodes_rows
        ]
        host_names = [nr[0] for nr in nodes_rows]

        # 3. Remote Hosts
        cursor_remotes = await db.execute("""
            SELECT DISTINCT remote_host
            FROM gossip_exchange
            WHERE remote_host IS NOT NULL AND remote_host != '' AND remote_host != 'unknown'
            ORDER BY remote_host
        """)
        unique_remote_hosts = [r[0] for r in await cursor_remotes.fetchall() if r[0]]

        # 4. Node Identities
        node_names = {}
        try:
            cursor_ident = await db.execute("SELECT ip, name FROM node_identity")
            for ir in await cursor_ident.fetchall():
                if ir[0] and ir[1]:
                    node_names[ir[0]] = ir[1]
        except Exception:
            pass

        summary_data = {
            "total_exchanges": row[0] or 0,
            "total_outgoing": row[1] or 0,
            "total_incoming": row[2] or 0,
            "total_accusations": total_accs,
            "total_rebuttals": total_rebuttals,
            "unique_hosts": host_names,
            "unique_remote_hosts": unique_remote_hosts,
            "node_names": node_names,
            "max_notes": max_notes,
            "max_payload_bytes": row[5] or 0,
            "total_data_bytes": row[6] or 0,
            "min_timestamp": str(row[7]) if row[7] is not None else None,
            "max_timestamp": str(row[8]) if row[8] is not None else None,
            "nodes_summary": nodes_list,
        }

        # 5. Timeline Bucket Aggregation
        where_tl = "WHERE host = ?" if host else ""
        params_tl = [host, buckets] if host else [buckets]
        cursor_tl = await db.execute(f"""
            SELECT 
                substr(timestamp, 1, 19) as ts_bucket,
                SUM(CASE WHEN direction = 'OUTGOING' THEN 1 ELSE 0 END) as out_cnt,
                SUM(CASE WHEN direction = 'INCOMING' THEN 1 ELSE 0 END) as in_cnt,
                SUM(COALESCE({data_col}, 0)) as total_bytes
            FROM gossip_exchange
            {where_tl}
            GROUP BY ts_bucket
            ORDER BY ts_bucket ASC
            LIMIT ?
        """, params_tl)
        tl_rows = await cursor_tl.fetchall()

        timeline_data = {
            "labels": [r[0] for r in tl_rows],
            "outgoing": [r[1] or 0 for r in tl_rows],
            "incoming": [r[2] or 0 for r in tl_rows],
            "bytes": [r[3] or 0 for r in tl_rows],
        }

    return {
        "status": status_info,
        "summary": summary_data,
        "timeline": timeline_data
    }


# Backwards-compatible aliases for cached browser clients / curl scripts
@app.get("/api/status")
async def get_status():
    data = await get_analytics()
    return data["status"]


@app.get("/api/summary")
async def get_summary():
    data = await get_analytics()
    return data["summary"]


# Standalone timeline endpoint for when the user selects a host
@app.get("/api/timeseries")
async def get_timeseries(host: Optional[str] = None, buckets: int = 50):
    target = resolve_db_path()
    if not os.path.exists(target):
        return {"labels": [], "outgoing": [], "incoming": [], "bytes": []}

    where = "WHERE host = ?" if host else ""
    params = [host, buckets] if host else [buckets]

    async with aiosqlite.connect(f"file:{target}?mode=ro", uri=True) as db:
        try:
            cur_cols = await db.execute("PRAGMA table_info(gossip_exchange)")
            cols = {r[1] for r in await cur_cols.fetchall()}
            data_col = "payload_data_size" if "payload_data_size" in cols else ("data_bytes" if "data_bytes" in cols else "0")

            cursor = await db.execute(f"""
                SELECT 
                    substr(timestamp, 1, 19) as ts_bucket,
                    SUM(CASE WHEN direction = 'OUTGOING' THEN 1 ELSE 0 END) as out_cnt,
                    SUM(CASE WHEN direction = 'INCOMING' THEN 1 ELSE 0 END) as in_cnt,
                    SUM(COALESCE({data_col}, 0)) as total_bytes
                FROM gossip_exchange
                {where}
                GROUP BY ts_bucket
                ORDER BY ts_bucket ASC
                LIMIT ?
            """, params)
            rows = await cursor.fetchall()
        except Exception:
            return {"labels": [], "outgoing": [], "incoming": [], "bytes": []}

    return {
        "labels": [r[0] for r in rows],
        "outgoing": [r[1] or 0 for r in rows],
        "incoming": [r[2] or 0 for r in rows],
        "bytes": [r[3] or 0 for r in rows],
    }


# -------------------------------------------------------------------------
# Dynamic Multi-Table Data & Counts Endpoints
# -------------------------------------------------------------------------

@app.get("/api/table_counts")
async def get_table_counts():
    target = resolve_db_path()
    if not os.path.exists(target):
        return {}
    async with aiosqlite.connect(f"file:{target}?mode=ro", uri=True) as db:
        try:
            cursor = await db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            tables = [r[0] for r in await cursor.fetchall()]
            counts = {}
            for t in tables:
                c = await db.execute(f"SELECT COUNT(*) FROM {t}")
                counts[t] = (await c.fetchone())[0]
            return counts
        except Exception:
            return {}


@app.get("/api/table_data")
async def get_table_data(
    table: str = "gossip_exchange",
    limit: int = 50,
    offset: int = 0,
    sort_order: str = "DESC",
    host: Optional[str] = None,
    remote_host: Optional[str] = None,
    direction: Optional[str] = None,
    search: Optional[str] = None,
):
    target = resolve_db_path()
    if not os.path.exists(target):
        return {"items": [], "total": 0, "columns": [], "table": table}

    allowed_tables = {"gossip_exchange", "rebuttal_events", "accusation_events", "note_events", "node_identity"}
    if table not in allowed_tables:
        return {"items": [], "total": 0, "columns": [], "table": table, "error": f"Invalid table '{table}'"}

    order_direction = "ASC" if sort_order.upper() == "ASC" else "DESC"

    async with aiosqlite.connect(f"file:{target}?mode=ro", uri=True) as db:
        try:
            c_check = await db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
            if not await c_check.fetchone():
                return {"items": [], "total": 0, "columns": [], "table": table}

            c_info = await db.execute(f"PRAGMA table_info({table})")
            columns = [r[1] for r in await c_info.fetchall()]

            where = []
            params = []

            if host:
                if "host" in columns:
                    where.append("host = ?")
                    params.append(host)
                elif "ip" in columns:
                    where.append("ip = ?")
                    params.append(host)

            if remote_host and "remote_host" in columns:
                where.append("remote_host = ?")
                params.append(remote_host)

            if direction and "direction" in columns:
                where.append("direction = ?")
                params.append(direction)

            if search:
                searchable = [c for c in columns if c in ("host", "remote_host", "accuser", "accused", "node_id", "name", "ip", "accused_nodes")]
                if searchable:
                    s_clause = " OR ".join(f"{c} LIKE ?" for c in searchable)
                    where.append(f"({s_clause})")
                    params.extend([f"%{search}%"] * len(searchable))

            where_clause = ("WHERE " + " AND ".join(where)) if where else ""

            cnt_cursor = await db.execute(f"SELECT COUNT(*) FROM {table} {where_clause}", params)
            total = (await cnt_cursor.fetchone())[0]

            sort_col = "timestamp" if "timestamp" in columns else columns[0]
            col_list_str = ", ".join(columns)

            select_sql = f"""
                SELECT {col_list_str}
                FROM {table}
                {where_clause}
                ORDER BY {sort_col} {order_direction}
                LIMIT ? OFFSET ?
            """
            cursor = await db.execute(select_sql, params + [limit, offset])
            rows = await cursor.fetchall()

            items = []
            for r in rows:
                item_dict = {}
                for k, v in zip(columns, r):
                    if k == "timestamp":
                        item_dict[k] = str(v)
                    elif k in ("rings", "accused_nodes") and isinstance(v, str):
                        try:
                            item_dict[k] = json.loads(v)
                        except Exception:
                            item_dict[k] = v
                    else:
                        item_dict[k] = v
                if table == "gossip_exchange":
                    if "payload_data_size" in item_dict and "data_bytes" not in item_dict:
                        item_dict["data_bytes"] = item_dict["payload_data_size"]
                    elif "data_bytes" in item_dict and "payload_data_size" not in item_dict:
                        item_dict["payload_data_size"] = item_dict["data_bytes"]
                items.append(item_dict)

            return {
                "items": items,
                "total": total,
                "columns": columns,
                "table": table,
            }
        except Exception as e:
            return {"items": [], "total": 0, "columns": [], "table": table, "error": str(e)}


@app.get("/api/exchanges")
async def get_exchanges(
    host: Optional[str] = None,
    peer: Optional[str] = None,
    remote_host: Optional[str] = None,
    direction: Optional[str] = None,
    has_accusations: bool = False,
    has_note: Optional[str] = None,
    search: Optional[str] = None,
    sort_order: str = "DESC",
    limit: int = 50,
    offset: int = 0
):
    return await get_table_data(
        table="gossip_exchange",
        limit=limit,
        offset=offset,
        sort_order=sort_order,
        host=host,
        remote_host=remote_host or peer,
        direction=direction,
        search=search,
    )


# -------------------------------------------------------------------------
# Time-series of DataBytes per Node
# -------------------------------------------------------------------------

@app.get("/api/bytes_per_node")
async def get_bytes_per_node(direction: Optional[str] = "OUTGOING"):
    target = resolve_db_path()
    if not os.path.exists(target):
        return {"nodes": {}, "total_per_node": {}, "direction": direction}

    where_parts = ["host != ''"]
    params_q = []
    if direction in ("OUTGOING", "INCOMING"):
        where_parts.append("direction = ?")
        params_q.append(direction)
    where_sql = "WHERE " + " AND ".join(where_parts)

    async with aiosqlite.connect(f"file:{target}?mode=ro", uri=True) as db:
        try:
            c_hosts = await db.execute("SELECT DISTINCT host FROM gossip_exchange WHERE host != '' ORDER BY host")
            hosts = [h[0] for h in await c_hosts.fetchall()]

            cursor = await db.execute(f"""
                SELECT timestamp, host, COALESCE(payload_data_size, data_bytes, 0)
                FROM gossip_exchange
                {where_sql}
                ORDER BY timestamp ASC
            """, params_q)
            rows = await cursor.fetchall()

            c_totals = await db.execute(f"""
                SELECT host, SUM(COALESCE(payload_data_size, data_bytes, 0)) as b
                FROM gossip_exchange
                {where_sql}
                GROUP BY host
                ORDER BY b DESC
            """, params_q)
            totals = {r[0]: r[1] or 0 for r in await c_totals.fetchall()}
        except Exception:
            return {"nodes": {}, "total_per_node": {}, "direction": direction}

    node_data: Dict[str, Dict[str, Any]] = {h: {"timestamps": [], "bytes": []} for h in hosts}
    for ts, h, b in rows:
        if h in node_data:
            node_data[h]["timestamps"].append(str(ts))
            node_data[h]["bytes"].append(b)

    return {
        "nodes": node_data,
        "total_per_node": totals,
        "direction": direction,
    }


@app.get("/api/rebuttals")
async def get_rebuttals(limit: int = 100):
    target = resolve_db_path()
    if not os.path.exists(target):
        return {"items": [], "total": 0}
    async with aiosqlite.connect(f"file:{target}?mode=ro", uri=True) as db:
        try:
            c = await db.execute("SELECT COUNT(*) FROM rebuttal_events")
            total = (await c.fetchone())[0]
            cursor = await db.execute(
                "SELECT timestamp, direction, host, remote_host, node_id, epoch, mask FROM rebuttal_events ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            rows = await cursor.fetchall()
            items = [
                {
                    "timestamp": str(r[0]),
                    "direction": r[1],
                    "host": r[2],
                    "remote_host": r[3],
                    "node_id": r[4],
                    "epoch": r[5],
                    "mask": r[6],
                }
                for r in rows
            ]
            return {"items": items, "total": total}
        except Exception:
            return {"items": [], "total": 0}


@app.get("/api/accusations")
async def get_accusations(limit: int = 100):
    target = resolve_db_path()
    if not os.path.exists(target):
        return {"items": [], "total": 0}
    async with aiosqlite.connect(f"file:{target}?mode=ro", uri=True) as db:
        try:
            c = await db.execute("SELECT COUNT(*) FROM accusation_events")
            total = (await c.fetchone())[0]
            cursor = await db.execute(
                "SELECT timestamp, direction, host, remote_host, accuser, accused, ring_num, epoch FROM accusation_events ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            rows = await cursor.fetchall()
            items = [
                {
                    "timestamp": str(r[0]),
                    "direction": r[1],
                    "host": r[2],
                    "remote_host": r[3],
                    "accuser": r[4],
                    "accused": r[5],
                    "ring_num": r[6],
                    "epoch": r[7],
                }
                for r in rows
            ]
            return {"items": items, "total": total}
        except Exception:
            return {"items": [], "total": 0}


@app.get("/", response_class=FileResponse)
async def dashboard_index():
    index_file = os.path.join(TEMPLATES_DIR, "index.html")
    return FileResponse(index_file)


def main():
    parser = argparse.ArgumentParser(description="Ifrit Telemetry Dashboard Server (FastAPI + SQLite)")
    default_target = "experiment_results"
    if not os.path.exists(default_target) and os.path.exists(os.path.join("..", "experiment_results")):
        default_target = os.path.join("..", "experiment_results")
    
    parser.add_argument(
        "target",
        nargs="?",
        default=default_target,
        help="Path to merged SQLite file or experiment directory containing telemetry databases (default: experiment_results)",
    )
    
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind server (default: 0.0.0.0)",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=8080,
        help="Port to bind server (default: 8080)",
    )
    args = parser.parse_args()

    global DB_TARGET
    DB_TARGET = os.path.abspath(args.target)

    print(f"==================================================")
    print(f"🔥 Starting Ifrit Telemetry Explorer (FastAPI)")
    print(f"📁 Target DB path or dir: {DB_TARGET}")
    print(f"🌐 Dashboard URL: http://localhost:{args.port}")
    print(f"==================================================")

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
