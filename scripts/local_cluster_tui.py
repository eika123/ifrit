#!/usr/bin/env python3
"""
3-Pane Flicker-Free Terminal Dashboard for Ifrit Local Cluster (Standard Library Curses)
Uses double-buffering (noutrefresh + doupdate) and persistent windows to completely eliminate flicker.
"""

import curses
import io
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback
from collections import deque


def _resolve_ifrit_config(repo_root):
    """Resolves IFRIT_CONFIG from env, IFRIT_CONFIG_PATHS, or the example template."""
    if env_cfg := os.environ.get("IFRIT_CONFIG"):
        return env_cfg

    raw_paths = os.environ.get("IFRIT_CONFIG_PATHS")
    if raw_paths:
        search_dirs = [p for p in raw_paths.split(os.pathsep) if p]
    else:
        search_dirs = [os.path.join(repo_root, "config"), repo_root, "/var/tmp"]

    for directory in search_dirs:
        base_dir = directory if os.path.isabs(directory) else os.path.join(repo_root, directory)
        for name in ("ifrit_config.yaml", "ifrit_config.yml"):
            candidate = os.path.join(base_dir, name)
            if os.path.isfile(candidate):
                return candidate

    example = os.path.join(repo_root, "config", "ifrit_config.example.yaml")
    return example if os.path.isfile(example) else None


def _is_ca_listening(port=8321, hosts=("127.0.0.1", "127.0.1.1", "localhost"), timeout=0.15):
    """Returns True if a TCP listener is accepting connections on the CA port."""
    for host in hosts:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


class ProcessPane:
    def __init__(self, title, color_pair, cmd, env=None, cwd=None):
        self.title = title
        self.color_pair = color_pair
        self.cmd = cmd
        self.env = env or {}
        self.cwd = cwd
        self.lines = deque(maxlen=1000)
        self.proc = None
        self.lock = threading.Lock()
        self.running = False
        self._stop_requested = False

    def append_line(self, text):
        with self.lock:
            self.lines.append(text)

    def start(self):
        self._stop_requested = False
        full_env = os.environ.copy()
        full_env.update(self.env)
        try:
            self.proc = subprocess.Popen(
                self.cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=full_env,
                cwd=self.cwd,
                start_new_session=True,
            )
        except FileNotFoundError:
            self.append_line(f"[ERROR] Binary not found: {self.cmd[0]}")
            self.append_line("[HINT] Ensure Go compilation succeeded before launching.")
            self.running = False
            return False
        except PermissionError:
            self.append_line(f"[ERROR] Permission denied executing: {self.cmd[0]}")
            self.running = False
            return False
        except OSError as exc:
            self.append_line(f"[ERROR] Failed to start process ({type(exc).__name__}): {exc}")
            self.running = False
            return False

        self.running = True
        threading.Thread(target=self._reader, daemon=True).start()
        return True

    def _diagnose_line(self, line):
        lower = line.lower()
        if "connection refused" in lower and ("8321" in lower or "certificaterequest" in lower):
            return "[HINT] Certificate Authority (CA :8321) is unreachable. Start/check the CA before launching nodes."
        if "address already in use" in lower:
            return "[HINT] Port conflict detected. Stop any existing Ifrit processes or containers and try again."
        if "error loading ca" in lower:
            return "[HINT] CA state could not be loaded. Try running 'just clean-ca-data' or passing --new."
        if "config file" in lower and "not found" in lower:
            return "[HINT] Missing ifrit_config.yaml. Run 'just config-init' or set IFRIT_CONFIG."
        return None

    def _reader(self):
        try:
            if self.proc is None or self.proc.stdout is None:
                self.append_line("[ERROR] Process stdout pipe is unavailable.")
                return

            for line in self.proc.stdout:
                clean = line.rstrip("\r\n")
                hint = self._diagnose_line(clean)
                with self.lock:
                    self.lines.append(clean)
                    if hint:
                        self.lines.append(hint)
        except (ValueError, io.UnsupportedOperation):
            # Expected when stdout pipe is closed during shutdown
            pass
        except OSError as exc:
            if not self._stop_requested:
                self.append_line(f"[ERROR] I/O error reading process output: {exc}")
        except Exception as exc:
            self.append_line(f"[ERROR] Unexpected reader error ({type(exc).__name__}): {exc}")
        finally:
            self.running = False
            if self.proc is not None and not self._stop_requested:
                try:
                    code = self.proc.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    code = self.proc.poll()
                if code is not None and code != 0:
                    self.append_line(f"[EXIT] Process terminated unexpectedly with exit code {code}")

    def stop(self):
        self._stop_requested = True
        if self.proc is None or self.proc.poll() is not None:
            return

        try:
            pgid = os.getpgid(self.proc.pid)
        except ProcessLookupError:
            return

        try:
            os.killpg(pgid, signal.SIGTERM)
            self.proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(pgid, signal.SIGKILL)
                self.proc.wait(timeout=1.0)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass
            except PermissionError as exc:
                print(f"[!] Permission error force-killing {self.title}: {exc}", file=sys.stderr)
        except ProcessLookupError:
            pass
        except PermissionError as exc:
            print(f"[!] Permission error stopping {self.title}: {exc}", file=sys.stderr)


def render_pane(win, title, color_pair, lines, is_running):
    """Draws pane to virtual buffer (noutrefresh) without triggering physical screen update."""
    win.erase()
    win.box()
    h, w = win.getmaxyx()

    status = " [RUNNING] " if is_running else " [STOPPED] "
    status_color = 2 if is_running else 4
    title_text = f" {title} "[:max(0, w - len(status) - 4)]

    try:
        win.addstr(0, 2, title_text, curses.A_BOLD | curses.color_pair(color_pair))
        win.addstr(0, max(2, w - len(status) - 2), status, curses.A_BOLD | curses.color_pair(status_color))
    except curses.error:
        pass

    content_h = h - 2
    content_w = w - 2
    if content_h > 0 and content_w > 0:
        visible = lines[-content_h:]
        for idx, line in enumerate(visible):
            truncated = line[:content_w]
            padded = truncated.ljust(content_w)
            attr = curses.A_NORMAL
            if truncated.startswith(("[ERROR]", "[EXIT]", "panic:")):
                attr = curses.A_BOLD | curses.color_pair(4)
            elif truncated.startswith(("[HINT]", "[WARN]")):
                attr = curses.A_BOLD | curses.color_pair(3)
            try:
                win.addstr(idx + 1, 1, padded, attr)
            except curses.error:
                pass

    win.noutrefresh()


def run_tui(stdscr, panes):
    try:
        curses.curs_set(0)
    except curses.error:
        pass

    stdscr.leaveok(True)
    stdscr.nodelay(True)
    stdscr.timeout(50)  # Check input at 20Hz

    if curses.has_colors():
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)
        curses.init_pair(2, curses.COLOR_GREEN, -1)
        curses.init_pair(3, curses.COLOR_YELLOW, -1)
        curses.init_pair(4, curses.COLOR_RED, -1)

    # Start CA first and verify it becomes reachable before booting gossip nodes
    ca_pane = panes[0]
    ca_started = ca_pane.start()
    ca_ready = False

    if ca_started:
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if ca_pane.proc is not None and ca_pane.proc.poll() is not None:
                break
            if _is_ca_listening(port=8321):
                ca_ready = True
                break
            time.sleep(0.1)

    if ca_ready:
        panes[1].start()
        time.sleep(0.4)
        panes[2].start()
    else:
        if not ca_started or (ca_pane.proc is not None and ca_pane.proc.poll() is not None):
            msg = "[ERROR] Cannot start gossip nodes: Certificate Authority (CA :8321) failed to start."
        else:
            msg = "[ERROR] Cannot start gossip nodes: CA did not become ready on port 8321 within 3.0s."
            ca_pane.append_line("[WARN] CA process is running, but port 8321 did not accept TCP connections in time.")
        panes[1].append_line(msg)
        panes[2].append_line(msg)

    last_h, last_w = -1, -1
    win_ca, win_n1, win_n2 = None, None, None

    while True:
        ch = stdscr.getch()
        if ch in (ord('q'), ord('Q'), 27, 3):  # 'q', ESC, or Ctrl+C
            break

        h, w = stdscr.getmaxyx()

        # Re-allocate windows ONLY when terminal size changes (eliminates flicker)
        if h != last_h or w != last_w:
            last_h, last_w = h, w
            stdscr.erase()
            if h < 12 or w < 40:
                try:
                    stdscr.addstr(0, 0, f"Terminal too small ({w}x{h}). Minimum 40x12.")
                    stdscr.noutrefresh()
                    curses.doupdate()
                except curses.error:
                    pass
                time.sleep(0.1)
                continue

            h_ca = max(4, h // 4)
            rem = h - h_ca - 1
            h_n1 = max(4, rem // 2)
            h_n2 = rem - h_n1

            win_ca = curses.newwin(h_ca, w, 0, 0)
            win_n1 = curses.newwin(h_n1, w, h_ca, 0)
            win_n2 = curses.newwin(h_n2, w, h_ca + h_n1, 0)

            win_ca.leaveok(True)
            win_n1.leaveok(True)
            win_n2.leaveok(True)

        if h < 12 or w < 40 or win_ca is None or win_n1 is None or win_n2 is None:
            time.sleep(0.1)
            continue

        with panes[0].lock:
            ca_lines = list(panes[0].lines)
        with panes[1].lock:
            n1_lines = list(panes[1].lines)
        with panes[2].lock:
            n2_lines = list(panes[2].lines)

        render_pane(win_ca, panes[0].title, panes[0].color_pair, ca_lines, panes[0].running)
        render_pane(win_n1, panes[1].title, panes[1].color_pair, n1_lines, panes[1].running)
        render_pane(win_n2, panes[2].title, panes[2].color_pair, n2_lines, panes[2].running)

        # Footer
        footer = " [q / Ctrl+C] Stop All Cluster Processes "
        footer_x = max(0, (w - len(footer)) // 2)
        try:
            stdscr.addstr(h - 1, 0, " " * (w - 1))
            stdscr.addstr(h - 1, footer_x, footer, curses.A_REVERSE)
        except curses.error:
            pass
        stdscr.noutrefresh()

        # Atomic double-buffer update: only diffs are pushed to terminal (zero flicker)
        curses.doupdate()
        time.sleep(0.05)


def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    ca_bin = "/tmp/ifrit-ca"
    node_bin = "/tmp/ifrit-gossip-node"

    env = os.environ.copy()
    env["PATH"] = f"{env.get('PATH', '')}:/usr/local/go/bin:{os.path.expanduser('~/go/bin')}"

    print("[*] Compiling latest Ifrit binaries...")
    try:
        subprocess.run(["go", "build", "-o", ca_bin, "./cmd/ca"], cwd=repo_root, env=env, check=True)
        subprocess.run(
            ["go", "build", "-o", node_bin, "./examples/gossip/gossipContentExample.go"],
            cwd=repo_root,
            env=env,
            check=True,
        )
    except FileNotFoundError:
        print("[-] Error: 'go' compiler not found in PATH. Install Go or add it to PATH.", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print(f"[-] Compilation failed (exit code {exc.returncode}). Fix build errors above and retry.", file=sys.stderr)
        sys.exit(exc.returncode)

    node_base_env = {}
    if ifrit_cfg := _resolve_ifrit_config(repo_root):
        node_base_env["IFRIT_CONFIG"] = ifrit_cfg

    panes = [
        ProcessPane(
            title="Certificate Authority (CA :8321)",
            color_pair=1,
            cmd=[ca_bin, "--new"],
            cwd=repo_root
        ),
        ProcessPane(
            title="Gossip Node 1 (RPC :9000, UDP :9001)",
            color_pair=2,
            cmd=[node_bin],
            env={**node_base_env, "IFRIT_HOSTNAME": "localhost", "IFRIT_TCP_PORT": "9000", "IFRIT_UDP_PORT": "9001"},
            cwd=repo_root
        ),
        ProcessPane(
            title="Gossip Node 2 (RPC :9002, UDP :9003)",
            color_pair=3,
            cmd=[node_bin],
            env={**node_base_env, "IFRIT_HOSTNAME": "localhost", "IFRIT_TCP_PORT": "9002", "IFRIT_UDP_PORT": "9003"},
            cwd=repo_root
        )
    ]

    exit_code = 0
    try:
        curses.wrapper(run_tui, panes)
    except KeyboardInterrupt:
        pass
    except curses.error as exc:
        exit_code = 1
        print(f"\n[-] Terminal UI error (ensure terminal supports curses and is at least 40x12): {exc}", file=sys.stderr)
    except Exception as exc:
        exit_code = 1
        print(f"\n[-] Unexpected TUI error ({type(exc).__name__}): {exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
    finally:
        for p in panes:
            p.stop()
        print("\n[+] All cluster processes stopped cleanly.")

    if exit_code:
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
