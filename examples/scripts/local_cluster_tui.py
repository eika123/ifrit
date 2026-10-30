#!/usr/bin/env python3
"""
3-Pane Flicker-Free Terminal Dashboard for Ifrit Local Cluster (Standard Library Curses)
Uses double-buffering (noutrefresh + doupdate) and persistent windows to completely eliminate flicker.
"""

import curses
import os
import signal
import subprocess
import sys
import threading
import time
from collections import deque

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

    def start(self):
        full_env = os.environ.copy()
        full_env.update(self.env)
        self.proc = subprocess.Popen(
            self.cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=full_env,
            cwd=self.cwd
        )
        self.running = True
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        try:
            for line in self.proc.stdout:
                clean = line.rstrip("\r\n")
                with self.lock:
                    self.lines.append(clean)
        except Exception:
            pass
        finally:
            self.running = False

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=1.0)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass


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
            try:
                win.addstr(idx + 1, 1, padded)
            except curses.error:
                pass

    win.noutrefresh()


def run_tui(stdscr, panes):
    try:
        curses.curs_set(0)
    except Exception:
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

    # Stagger process starts
    panes[0].start()
    time.sleep(1.2)  # Give CA a moment to initialize
    panes[1].start()
    time.sleep(0.4)
    panes[2].start()

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

        if h < 12 or w < 40:
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
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    ca_bin = "/tmp/ifrit-ca"
    node_bin = "/tmp/ifrit-gossip-node"

    env = os.environ.copy()
    env["PATH"] = f"{env.get('PATH', '')}:/usr/local/go/bin:{os.path.expanduser('~/go/bin')}"

    print("[*] Compiling latest Ifrit binaries...")
    subprocess.run(["go", "build", "-o", ca_bin, "./cmd/ca"], cwd=repo_root, env=env, check=True)
    subprocess.run(["go", "build", "-o", node_bin, "./examples/gossip/gossipContentExample.go"], cwd=repo_root, env=env, check=True)

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
            env={"IFRIT_HOSTNAME": "localhost", "IFRIT_TCP_PORT": "9000", "IFRIT_UDP_PORT": "9001"},
            cwd=repo_root
        ),
        ProcessPane(
            title="Gossip Node 2 (RPC :9002, UDP :9003)",
            color_pair=3,
            cmd=[node_bin],
            env={"IFRIT_HOSTNAME": "localhost", "IFRIT_TCP_PORT": "9002", "IFRIT_UDP_PORT": "9003"},
            cwd=repo_root
        )
    ]

    try:
        curses.wrapper(run_tui, panes)
    except KeyboardInterrupt:
        pass
    finally:
        for p in panes:
            p.stop()
        print("\n[+] All cluster processes stopped cleanly.")


if __name__ == "__main__":
    main()
