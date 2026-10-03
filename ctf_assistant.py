#!/usr/bin/env python3
"""
ctf_assistant.py — Modular interactive CTF Reconnaissance & Assistant tool.

Author:  zadwen
License: MIT

Automates the standard early-recon workflow used in CTF / lab environments
(HackTheBox, TryHackMe, OSCP-style labs, your own test VMs), and actively
hunts for flags in whatever it finds instead of just listing services:

    1. Target validation
    2. Tool-availability checklist
    3. Fast port sweep (Nmap)                      [skippable with --ports]
    4. Deep -sC -sV scan on discovered ports only
    5. Optional quick UDP sweep                     [--udp]
    6. Service-specific enumeration + LOOT DOWNLOAD + FLAG SCANNING:
         - HTTP: gobuster/ffuf with extensions, common CTF paths fetched
           and grepped for flags, discovered 200-OK paths auto-fetched
           and grepped too, nikto
         - SMB: anonymous share listing -> auto-download files -> flag scan
         - FTP: anonymous login via ftplib (no external ftp client needed)
           -> recursive loot download -> flag scan
    7. searchsploit lookups per detected service/version (if installed)
    8. A "Quick Wins" panel (flags found, working anon access, exploit-db
       hits) followed by a general "Next Steps" checklist
    9. A final full-output-directory flag sweep, so even a flag that
       slipped past a spot-check still gets caught

IMPORTANT: Only run this against systems you own or are explicitly
authorized to test (CTF boxes, your own lab VMs, engagements you're
scoped for). Unauthorized scanning of systems you don't control is
illegal in most jurisdictions.

Usage:
    python3 ctf_assistant.py                       # interactive prompt
    python3 ctf_assistant.py -t 10.10.11.42         # non-interactive
    python3 ctf_assistant.py -t 10.10.11.42 --fast  # top-1000 ports only
    python3 ctf_assistant.py -t 10.10.11.42 -p 80,22,445   # skip Phase 1
    python3 ctf_assistant.py -t 10.10.11.42 --udp --thorough
    python3 ctf_assistant.py --help
"""

from __future__ import annotations

import argparse
import csv
import ftplib
import io
import ipaddress
import json
import hashlib
from urllib.parse import urljoin, urlsplit
from ctf_evidence import (detect, ArtifactScanner, merge_findings, parse_nmap, write_json_report)
from ctf_web import WebMapper, canonical_url, origin
from ctf_triage import write_triage
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

# --------------------------------------------------------------------------
# Optional 'rich' UI layer — falls back to plain ANSI if not installed.
# --------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.text import Text
    from rich import box

    # markup=False: we always apply color via the explicit style= kwarg, never
    # inline [tag]...[/tag] markup, so Rich's markup parser has nothing to do
    # except silently eat literal brackets in our own text ("[resume]", "[i]"
    # were vanishing from output) and, worse, in untrusted CTF-box content we
    # display verbatim (a flag or filename containing bracket sequences could
    # be silently corrupted before it ever reaches the screen). Disabling it
    # makes every bracketed string print exactly as given.
    console = Console(markup=False)
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    console = None


# ==========================================================================
# Branding — evidence analysis lives in ctf_evidence.py
# ==========================================================================

class Brand:
    NAME = "CTF Recon Assistant"
    AUTHOR = "zadwen"
    VERSION = "2.2.0"
    REPO = "github.com/zadwen/ctf-assistant"

    BANNER = r"""
   ______ ______ ______     ___                       
  / ____//_  __// ____/    /   |  _____________  ____ 
 / /      / /  / /_       / /| | / ___/ ___/ __ \/ __ \
/ /___   / /  / __/      / ___ |(__  |__  ) /_/ / / / /
\____/  /_/  /_/        /_/  |_/____/____/\____/_/ /_/ 
"""


# ==========================================================================
# Minimal ANSI fallback (used only if rich isn't installed)
# ==========================================================================

class Ansi:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GREY = "\033[90m"


def out(msg: str, color: str = "", bold: bool = False) -> None:
    """Print helper that uses rich if available, else plain ANSI."""
    if RICH_AVAILABLE:
        style = color
        if bold:
            style = f"bold {color}".strip()
        console.print(msg, style=style or None)
    else:
        prefix = ""
        if bold:
            prefix += Ansi.BOLD
        prefix += {
            "red": Ansi.RED,
            "green": Ansi.GREEN,
            "yellow": Ansi.YELLOW,
            "blue": Ansi.BLUE,
            "magenta": Ansi.MAGENTA,
            "cyan": Ansi.CYAN,
            "grey": Ansi.GREY,
            "bright_black": Ansi.GREY,
            "": "",
        }.get(color, "")
        print(f"{prefix}{msg}{Ansi.RESET}")


def section(title: str) -> None:
    if RICH_AVAILABLE:
        # Text(...) applies the style directly rather than via inline
        # [tag]...[/tag] markup, so this keeps working correctly now that
        # the console itself has markup=False (see console instantiation
        # above for why: bracketed content elsewhere must print literally).
        console.rule(Text(title, style="bold cyan"))
    else:
        print(f"\n{Ansi.BOLD}{Ansi.CYAN}=== {title} ==={Ansi.RESET}")


# ==========================================================================
# Flag-detection engine
# ==========================================================================
# CTF flags are almost always of the form NAME{...} — flag{...}, HTB{...},
# CTF{...}, picoCTF{...}, THM{...}, root{...}, etc. This regex catches the
# general shape rather than hardcoding every event's naming convention.

FLAG_REGEX = re.compile(r"\b[A-Za-z][A-Za-z0-9_]{1,24}\{[^{}\r\n]{2,120}\}")

# Filenames that are worth flagging even before we've looked inside them —
# seeing one in a directory listing (FTP/SMB/gobuster) is itself a signal.
INTERESTING_FILENAMES = {
    "flag.txt", "flag", "flag.php", "flag.html", "user.txt", "root.txt",
    "proof.txt", "local.txt", "flag.md", "secret.txt", ".flag",
}

MAX_LOOT_FILE_BYTES = 3 * 1024 * 1024  # don't download/scan huge files


def flag_scan(text: str) -> list[str]:
    """Return de-duplicated flag-shaped matches found in text."""
    if not text:
        return []
    seen = []
    for m in FLAG_REGEX.finditer(text):
        candidate = m.group(0)
        if candidate not in seen:
            seen.append(candidate)
    return seen


def record_flags(ctx: "ScanContext", text: str, source: str) -> list[str]:
    """Scan text for flags, record any new ones on ctx, return what was found."""
    findings = detect(text, source, ctx.flag_prefixes, ctx.include_hashes)
    merge_findings(ctx, findings)
    return list(dict.fromkeys(f['value'] for f in findings if f['confidence'] != 'low'))



def filename_is_interesting(name: str) -> bool:
    return name.strip().lower() in INTERESTING_FILENAMES


# ==========================================================================
# Data model
# ==========================================================================

@dataclass
class OpenPort:
    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    state: str = "open"


@dataclass
class ScanContext:
    target: str
    output_dir: Path
    open_ports: list[OpenPort] = field(default_factory=list)
    tool_status: dict[str, bool] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)
    quick_wins: list[str] = field(default_factory=list)
    flags_found: list[tuple[str, str]] = field(default_factory=list)  # (flag, source)
    exploit_hits: list[str] = field(default_factory=list)
    flag_evidence: list[dict] = field(default_factory=list)
    analysis_warnings: list[str] = field(default_factory=list)
    flag_prefixes: list[str] = field(default_factory=list)
    include_hashes: bool = False
    web_results: list[dict] = field(default_factory=list)
    next_steps: list[dict] = field(default_factory=list)
    crawl_enabled: bool = True
    web_pages: int = 60
    web_depth: int = 3
    web_seconds: int = 120
    web_delay: float = 0.1


# ==========================================================================
# Validation helpers
# ==========================================================================

def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_hostname(value: str) -> bool:
    """RFC-1123-ish hostname check."""
    if len(value) > 253:
        return False
    if value.endswith("."):
        value = value[:-1]
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in value.split("."))


def resolve_target(value: str) -> Optional[str]:
    """Return the IP the target resolves to (or the IP itself), or None on failure."""
    if is_valid_ip(value):
        return value
    if is_valid_hostname(value):
        try:
            return socket.gethostbyname(value)
        except socket.gaierror:
            return None
    return None


# ==========================================================================
# Tool availability
# ==========================================================================

CORE_TOOLS = {
    "nmap": "Port scanning & service/version detection",
    "gobuster": "Directory/file brute-forcing (preferred)",
    "ffuf": "Directory/file brute-forcing (fallback if gobuster missing)",
    "nikto": "Web server vulnerability scanning",
    "smbclient": "SMB anonymous share enumeration + loot download",
}

OPTIONAL_TOOLS = {
    "searchsploit": "Offline exploit-db lookup by detected service/version",
    "rpcclient": "Anonymous/null-session MSRPC enumeration (ships with the smbclient package)",
    "enum4linux-ng": "One-shot comprehensive SMB/AD null-session enumeration",
}

APT_PACKAGE_NAME = {
    "gobuster": "gobuster",
    "nikto": "nikto",
    "smbclient": "smbclient",  # also provides rpcclient
    "nmap": "nmap",
}


def check_tools() -> dict[str, bool]:
    all_tools = {**CORE_TOOLS, **OPTIONAL_TOOLS}
    return {tool: shutil.which(tool) is not None for tool in all_tools}


def print_tool_checklist(status: dict[str, bool]) -> None:
    section("Prerequisite Tool Check")
    if RICH_AVAILABLE:
        table = Table(box=box.SIMPLE_HEAVY)
        table.add_column("Tool")
        table.add_column("Purpose")
        table.add_column("Status", justify="center")
        for tool, purpose in {**CORE_TOOLS, **OPTIONAL_TOOLS}.items():
            ok = status.get(tool, False)
            mark = Text("READY", style="bold green") if ok else Text("MISSING", style="bold red")
            if tool in OPTIONAL_TOOLS and not ok:
                mark = Text("OPTIONAL", style="yellow")
            table.add_row(tool, purpose, mark)
        console.print(table)
        out("  Note: anonymous FTP checks use Python's built-in ftplib — no "
            "external 'ftp' client needed.", "bright_black")
    else:
        for tool, purpose in {**CORE_TOOLS, **OPTIONAL_TOOLS}.items():
            ok = status.get(tool, False)
            mark = f"{Ansi.GREEN}READY{Ansi.RESET}" if ok else f"{Ansi.RED}MISSING{Ansi.RESET}"
            print(f"  {tool:<12} {purpose:<50} [{mark}]")

    missing = [t for t in CORE_TOOLS if not status.get(t, False)]
    # gobuster/ffuf are interchangeable — don't hard-fail on one of the pair
    hard_missing = [
        t for t in missing
        if not (t in ("gobuster", "ffuf") and status.get("ffuf" if t == "gobuster" else "gobuster"))
    ]
    if hard_missing:
        out(f"\n  Missing tools: {', '.join(hard_missing)}. Install with e.g.:", "yellow")
        apt_pkgs = [APT_PACKAGE_NAME.get(t, t) for t in hard_missing if t != "ffuf"]
        if apt_pkgs:
            out(f"    sudo apt install {' '.join(apt_pkgs)}", "yellow")
        if "ffuf" in hard_missing:
            out("    sudo apt install ffuf   # or: go install github.com/ffuf/ffuf/v2@latest", "yellow")
        out("  Affected phases will be skipped automatically.\n", "yellow")
    else:
        out("\n  All core tools available.\n", "green")

    if not status.get("searchsploit", False):
        out("  Tip: install searchsploit for offline exploit-db lookups "
            "(git clone https://gitlab.com/exploit-database/exploitdb, "
            "or included by default on Kali).", "bright_black")
    if not status.get("rpcclient", False):
        out("  Tip: rpcclient (anonymous MSRPC enumeration against Windows/AD "
            "targets) ships with the smbclient package — install that and "
            "you get both.", "bright_black")
    if not status.get("enum4linux-ng", False):
        out("  Tip: install enum4linux-ng for one-shot comprehensive SMB/AD "
            "null-session enumeration (pip install enum4linux-ng).", "bright_black")
    out("", "")


# ==========================================================================
# Command runner
# ==========================================================================

def mark_done(marker_path: Path) -> None:
    """Write a sentinel file indicating a phase finished cleanly (rc == 0).
    --resume checks for this instead of just "does the log file exist" —
    a log file can exist and still be truncated (e.g. a gobuster/nikto run
    that hit its timeout writes a partial log with an [ERROR] note, but the
    file is still there). Only a rc==0 completion earns the sentinel, so a
    truncated or failed run is correctly re-run on --resume instead of being
    silently trusted."""
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    marker_path.write_text(datetime.now().isoformat())


def phase_is_done(marker_path: Path) -> bool:
    return marker_path.exists()


def run_command(cmd: list[str], log_path: Path, timeout: Optional[int] = None,
                 cwd: Optional[Path] = None) -> tuple[int, str]:
    """
    Run a command, capturing full output to log_path. Returns
    (returncode, combined_output). Raises KeyboardInterrupt upward
    untouched so the caller can handle Ctrl+C.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8", errors="replace",
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
        )
        output = proc.stdout or ""
        log_path.write_text(output)
        return proc.returncode, output
    except FileNotFoundError:
        msg = f"[ERROR] Command not found: {cmd[0]}"
        log_path.write_text(msg)
        return 127, msg
    except subprocess.TimeoutExpired as e:
        partial = e.stdout.decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        msg = partial + f"\n[ERROR] Command timed out after {timeout}s: {' '.join(cmd)}"
        log_path.write_text(msg)
        return 124, msg


def spinner_run(description: str, cmd: list[str], log_path: Path,
                 timeout: Optional[int] = None, cwd: Optional[Path] = None) -> tuple[int, str]:
    """Run a command with a live spinner if rich is available."""
    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(description, total=None)
            result = run_command(cmd, log_path, timeout=timeout, cwd=cwd)
            progress.update(task, completed=1)
        return result
    else:
        print(f"  -> {description} ...", end="", flush=True)
        result = run_command(cmd, log_path, timeout=timeout, cwd=cwd)
        print(" done.")
        return result


# ==========================================================================
# Phase 1: Quick Nmap scan
# ==========================================================================

def phase_quick_scan(ctx: ScanContext, fast: bool = False, min_rate: int = 1000) -> list[int]:
    section("Phase 1 — Quick Port Sweep (Nmap)")
    log_path = ctx.output_dir / "nmap" / "quick_scan.txt"

    port_spec = ["--top-ports", "1000"] if fast else ["-p-"]
    cmd = [
        "nmap",
        "-T4",
        "--min-rate", str(min_rate),
        *port_spec,
        "-Pn",              # skip host discovery — CTF boxes often block ICMP
        "--open",
        "-oN", str(log_path.with_suffix(".nmap")),
        "-oX", str(log_path.with_suffix(".xml")),
        ctx.target,
    ]
    label = "top 1000 ports (--fast)" if fast else "all 65535 ports"
    out(f"  Running: {' '.join(cmd)}", "bright_black")
    rc, output = spinner_run(f"Scanning {label}...", cmd, log_path)

    ports: list[int] = []
    for line in output.splitlines():
        m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", line.strip())
        if m:
            ports.append(int(m.group(1)))

    if rc == 127:
        out("  nmap is not installed — skipping Phase 1 and Phase 2.", "red")
    elif not ports:
        out("  No open ports found (or host filtered/down). Check connectivity.", "yellow")
    else:
        out(f"  Open ports discovered: {', '.join(str(p) for p in ports)}", "green", bold=True)
        if fast:
            out("  (--fast only checked the top 1000 ports — re-run without "
                "--fast, or add --ports once you've triaged, to be sure "
                "nothing on an unusual port was missed.)", "yellow")

    if rc == 0:
        mark_done(ctx.output_dir / "nmap" / "quick_scan.done")
    else:
        out(f"  (rc={rc} — not marking Phase 1 complete; --resume will re-run it.)", "bright_black")

    return ports


# ==========================================================================
# Phase 1b: Optional quick UDP sweep
# ==========================================================================

def phase_udp_scan(ctx: ScanContext, top_ports: int = 50) -> None:
    section(f"Phase 1b — Quick UDP Sweep (top {top_ports} ports)")
    log_path = ctx.output_dir / "nmap" / "udp_scan.txt"
    cmd = [
        "nmap", "-sU", "-Pn", "--top-ports", str(top_ports),
        "-oN", str(log_path.with_suffix(".nmap")),
        "-oX", str(log_path.with_suffix(".xml")),
        ctx.target,
    ]
    out(f"  Running: {' '.join(cmd)}", "bright_black")
    out("  Note: UDP scanning usually requires root/sudo privileges.", "bright_black")
    rc, output = spinner_run(f"Scanning top {top_ports} UDP ports...", cmd, log_path, timeout=240)

    if rc == 127:
        out("  nmap not installed — skipping.", "red")
        return
    if "requires root privileges" in output.lower() or "permission denied" in output.lower():
        out("  UDP scan needs elevated privileges — re-run the whole script "
            "with sudo to get UDP results.", "yellow")
        return  # not marking done — this wasn't a real scan attempt

    found = []
    for line in output.splitlines():
        m = re.match(r"^(\d+)/udp\s+(open|open\|filtered)\s+(\S+)", line.strip())
        if m:
            port_num = int(m.group(1))
            service = m.group(3)
            found.append(port_num)
            if not any(p.port == port_num and p.protocol == "udp" for p in ctx.open_ports):
                ctx.open_ports.append(OpenPort(port_num, "udp", service, state=m.group(2)))

    if found:
        out(f"  UDP ports open/open|filtered: {', '.join(str(p) for p in found)}", "green", bold=True)
    else:
        out(f"  No open UDP ports found in top {top_ports}.", "yellow")

    if rc == 0:
        mark_done(ctx.output_dir / "nmap" / "udp_scan.done")
    else:
        out(f"  (rc={rc} — not marking UDP sweep complete; --resume will re-run it.)", "bright_black")


# ==========================================================================
# Phase 2: Deep scan on discovered ports only
# ==========================================================================

def _apply_deep_scan_output(ctx: ScanContext, output: str) -> None:
    """Parse nmap -sC -sV 'PORT STATE SERVICE VERSION' lines into ctx.open_ports,
    and flag-scan the raw output. Shared between a live run and --resume (which
    re-parses a previously-saved log instead of re-running nmap)."""
    for line in output.splitlines():
        m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$", line.strip())
        if m:
            port_num = int(m.group(1))
            proto = m.group(2)
            service = m.group(3)
            version = m.group(4).strip()
            existing = next((p for p in ctx.open_ports if p.port == port_num and p.protocol == proto), None)
            if existing:
                existing.service = service
                existing.version = version
            else:
                ctx.open_ports.append(OpenPort(port_num, proto, service, version))

    new_flags = record_flags(ctx, output, "nmap -sC -sV output")
    for f in new_flags:
        out(f"  [!] Possible flag spotted directly in nmap output: {f}", "magenta", bold=True)
        ctx.quick_wins.append(f"Flag-shaped string in nmap -sC output: {f}")


def phase_deep_scan(ctx: ScanContext, ports: list[int]) -> None:
    section("Phase 2 — Deep Scan (-sC -sV) on Open Ports")
    if not ports:
        out("  Skipped — no open ports from Phase 1.", "yellow")
        return

    port_list = ",".join(str(p) for p in ports)
    log_path = ctx.output_dir / "nmap" / "deep_scan.txt"

    cmd = [
        "nmap",
        "-sC", "-sV",
        "-Pn",
        "-p", port_list,
        "-oN", str(log_path.with_suffix(".nmap")),
        "-oX", str(log_path.with_suffix(".xml")),
        ctx.target,
    ]
    out(f"  Running: {' '.join(cmd)}", "bright_black")
    rc, output = spinner_run(f"Running -sC -sV against {port_list}...", cmd, log_path)

    if rc == 127:
        out("  nmap not installed — skipping.", "red")
        return

    _apply_deep_scan_output(ctx, output)
    out(f"  Deep scan complete. Log: {log_path.with_suffix('.nmap')}", "green")

    if rc == 0:
        mark_done(ctx.output_dir / "nmap" / "deep_scan.done")
    else:
        out(f"  (rc={rc} — not marking Phase 2 complete; --resume will re-run it.)", "bright_black")


def resume_load_quick_scan(ctx: ScanContext) -> Optional[list[int]]:
    """--resume support: if Phase 1 completed cleanly in this output dir
    (marked by quick_scan.done, written only on rc==0), reuse the ports it
    found instead of re-scanning all 65535 ports again. A log file that
    exists WITHOUT the sentinel means the previous run was interrupted or
    failed mid-scan — its contents may be incomplete, so it's ignored here
    and Phase 1 is re-run from scratch instead of silently trusting a
    partial port list."""
    marker = ctx.output_dir / "nmap" / "quick_scan.done"
    log_path = ctx.output_dir / "nmap" / "quick_scan.nmap"
    if not phase_is_done(marker) or not log_path.is_file():
        if log_path.exists():
            out(f"  [resume] Found {log_path} but no completion marker — "
                f"it looks like that scan was interrupted. Re-running Phase 1 "
                f"rather than trusting a possibly-partial port list.", "yellow")
        return None
    text = log_path.read_text(errors="replace")
    ports = []
    for line in text.splitlines():
        m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", line.strip())
        if m:
            ports.append(int(m.group(1)))
    if ports:
        out(f"  [resume] Reusing Phase 1 results from {log_path} — "
            f"found ports {ports} — skipping the full sweep.", "blue")
    return ports or None


def resume_load_deep_scan(ctx: ScanContext) -> bool:
    """--resume support: if Phase 2 completed cleanly (deep_scan.done exists),
    re-parse the saved log into ctx.open_ports instead of re-running -sC -sV.
    Same reasoning as resume_load_quick_scan: no sentinel means the run was
    interrupted/failed, so it's correctly re-run rather than trusted."""
    marker = ctx.output_dir / "nmap" / "deep_scan.done"
    log_path = ctx.output_dir / "nmap" / "deep_scan.nmap"
    if not phase_is_done(marker) or not log_path.is_file():
        if log_path.exists():
            out(f"  [resume] Found {log_path} but no completion marker — "
                f"re-running Phase 2 rather than trusting a possibly-partial "
                f"result.", "yellow")
        return False
    section("Phase 2 — Deep Scan (-sC -sV) on Open Ports [resumed]")
    out(f"  [resume] Reusing existing deep scan log: {log_path}", "blue")
    _apply_deep_scan_output(ctx, log_path.read_text(errors="replace"))
    return True


# ==========================================================================
# searchsploit integration
# ==========================================================================

def searchsploit_lookup(ctx: ScanContext, port: OpenPort, tool_status: dict[str, bool]) -> None:
    if not tool_status.get("searchsploit"):
        return
    service = (port.service or "").strip().lower()
    version = (port.version or "").strip()
    if not service or service in ("tcpwrapped", "unknown", "filtered"):
        return
    query = f"{service} {version}".strip()
    if len(query) < 4:
        return  # not enough signal to search on

    log_path = ctx.output_dir / "searchsploit" / f"port_{port.port}.txt"
    cmd = ["searchsploit", "--no-color", query]
    rc, output = spinner_run(f"searchsploit lookup: {query!r}...", cmd, log_path, timeout=30)

    if rc == 127:
        return
    lowered = output.lower()
    if "no results" in lowered and "exploit title" not in lowered:
        return
    if "exploit title" in lowered:
        hit_count = len([
            ln for ln in output.splitlines()
            if "|" in ln and "exploit title" not in ln.lower() and not ln.strip().startswith("-")
        ])
        msg = (f"Port {port.port} ({service} {version}) -> searchsploit found "
               f"{hit_count} potential exploit-db match(es). See {log_path}")
        ctx.recommendations.append(msg)
        ctx.quick_wins.append(msg)
        out(f"  [!] {msg}", "magenta", bold=True)


# ==========================================================================
# Phase 3: Service-specific enumeration
# ==========================================================================

HTTP_PORTS = {80, 443, 8000, 8008, 8080, 8443, 8888}
SMB_PORTS = {139, 445}
FTP_PORTS = {21}

# Service-name fallbacks: nmap's -sV output is used to catch services running
# on non-standard ports (common on CTF boxes) that the fixed port sets above
# would otherwise miss.
HTTP_SERVICE_NAMES = {"http", "https", "http-proxy", "http-alt", "ssl/http"}
SMB_SERVICE_NAMES = {"microsoft-ds", "netbios-ssn", "smb"}
FTP_SERVICE_NAMES = {"ftp"}

# Windows/AD-related ports — any of these present triggers the dedicated
# Windows/AD enumeration phase (phase_windows_ad_enum), since these boxes
# need a genuinely different playbook than a Linux/web CTF target.
KERBEROS_PORTS = {88}
RPC_PORT = 135
SMB_RELATED_PORTS = {139, 445}
LDAP_PORTS = {389, 636, 3268, 3269}
RDP_PORTS = {3389}
WINRM_PORTS = {5985, 5986}
WINDOWS_TRIGGER_PORTS = (KERBEROS_PORTS | {RPC_PORT} | SMB_RELATED_PORTS | LDAP_PORTS
                          | RDP_PORTS | WINRM_PORTS)
# Windows' ephemeral/dynamic RPC endpoint range — ports here reported as
# "unknown" are worth a targeted msrpc-enum pass to name what's actually
# listening instead of leaving them as a dead end.
WINDOWS_DYNAMIC_RPC_RANGE = range(49152, 65536)

# Candidate wordlist locations, in preference order. The Kali convention
# (/usr/share/wordlists/dirb/common.txt) is checked first since it's the
# most commonly referenced path; the plain `dirb` package on Ubuntu/Zorin
# installs to /usr/share/dirb/wordlists/common.txt instead.
WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
]

# Extensions worth checking automatically — these are what actually hold
# flags/creds on CTF web boxes (backup files, configs, source dumps).
CTF_EXTENSIONS = "php,txt,html,bak,zip,old,conf,config,js,sql,env"

# Paths worth fetching directly regardless of what dir-busting finds —
# fast, low-cost, and frequently where the first foothold/flag lives.
COMMON_CTF_PATHS = [
    "robots.txt", "sitemap.xml", ".git/HEAD", ".git/config",
    "flag.txt", "flag", "flag.php", "backup.zip", "config.php.bak",
    ".env", "admin/", "login/", "server-status",
]

MAX_AUTO_FETCHED_PATHS = 15  # cap on gobuster-discovered paths we auto-fetch


def _matches(port: "OpenPort", port_set: set[int], service_names: set[str]) -> bool:
    if port.port in port_set:
        return True
    service = port.service.lower()
    return any(name in service for name in service_names)


def find_wordlist(thorough: bool = False, override: Optional[str] = None) -> Optional[str]:
    if override:
        return override if Path(override).exists() else None
    candidates = WORDLIST_CANDIDATES if thorough else WORDLIST_CANDIDATES[:2]
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    # fall through to any candidate that exists, even in non-thorough mode
    for candidate in WORDLIST_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return None


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if url_origin(req.full_url) != url_origin(newurl):
            raise urllib.error.HTTPError(newurl, code, "Cross-origin redirect blocked", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def url_origin(url):
    parsed = urlsplit(url)
    return parsed.scheme.lower(), parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


def safe_fetch(url: str, timeout: int = 6) -> Optional[tuple[int, str]]:
    """GET a URL, ignoring TLS cert errors (common on CTF self-signed certs).
    Returns (status_code, text) on any HTTP response, or None on network
    failure. Truncates to MAX_LOOT_FILE_BYTES."""
    ctx_ssl = ssl.create_default_context()
    ctx_ssl.check_hostname = False
    ctx_ssl.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (ctf-assistant)"})
    try:
        opener = urllib.request.build_opener(SameOriginRedirect(), urllib.request.HTTPSHandler(context=ctx_ssl))
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(MAX_LOOT_FILE_BYTES)
            text = body.decode("utf-8", errors="replace")
            return resp.status, text
    except urllib.error.HTTPError as e:
        try:
            body = e.read(MAX_LOOT_FILE_BYTES)
            text = body.decode("utf-8", errors="replace")
        except Exception:
            text = ""
        return e.code, text
    except Exception:
        return None


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def parse_gobuster_paths(output: str) -> list[str]:
    paths = []
    for line in output.splitlines():
        clean_line = ANSI_ESCAPE_RE.sub("", line).strip()
        m = re.match(r"^(\S+)\s+\(Status:\s*(\d+)\)", clean_line)
        if m and m.group(2) == "200" and m.group(1) not in paths:
            paths.append(m.group(1))
    return paths


def parse_ffuf_csv_paths(csv_text: str) -> list[str]:
    # Defense-in-depth: ffuf's -of csv output shouldn't carry color codes
    # (they go to the terminal, not -o), but the same class of bug bit us
    # with gobuster, so strip unconditionally before parsing.
    csv_text = ANSI_ESCAPE_RE.sub("", csv_text)
    paths = []
    try:
        reader = csv.DictReader(io.StringIO(csv_text))
        for row in reader:
            if row.get("status") == "200" and row.get("url"):
                paths.append(row["url"])
    except Exception:
        pass
    return paths


def extract_robots_paths(text: str) -> list[str]:
    """Pull Disallow:/Allow: paths out of a robots.txt body — these are
    the site owner's own map of what they didn't want indexed, which in
    a CTF is often exactly where the flag is."""
    paths = []
    for line in text.splitlines():
        m = re.match(r"(?i)^\s*(disallow|allow)\s*:\s*(\S+)", line)
        if m:
            p = m.group(2).strip()
            if p and p != "/":
                paths.append(p.lstrip("/"))
    return paths


def extract_sitemap_paths(text: str) -> list[str]:
    """Pull <loc>...</loc> URLs out of a sitemap.xml body."""
    return [m.group(1).strip() for m in re.finditer(r"<loc>(.*?)</loc>", text, re.IGNORECASE)]


def auto_fetch_and_scan(ctx: ScanContext, base_url: str, paths: list[str],
                         out_dir: Path) -> list[tuple[str, str]]:
    """Fetch each path relative to base_url, save 200-OK bodies, flag-scan
    them, and return the (path, text) pairs that came back 200 so the
    caller can chain further discovery (e.g. robots.txt -> its Disallow
    targets)."""
    fetched: list[tuple[str, str]] = []
    for rel_path in paths[:MAX_AUTO_FETCHED_PATHS]:
        url = urljoin(base_url, rel_path)
        try:
            if url_origin(url) != url_origin(base_url) or urlsplit(url).username:
                ctx.analysis_warnings.append(f"Skipped out-of-origin discovery: {url}")
                continue
        except ValueError:
            continue
        result = safe_fetch(url)
        if result is None:
            continue
        status, text = result
        if status != 200 or not text.strip():
            continue

        safe_name = (re.sub(r"[^\w.-]", "_", rel_path)[:100] or "root") + "_" + hashlib.sha256(url.encode()).hexdigest()[:12]
        save_path = out_dir / f"fetched_{safe_name}.txt"
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(text[:MAX_LOOT_FILE_BYTES])
        fetched.append((rel_path, text))

        new_flags = record_flags(ctx, text, f"HTTP GET {url}")
        if new_flags:
            for f in new_flags:
                out(f"    [!] FLAG CANDIDATE at {url}: {f}", "magenta", bold=True)
                ctx.quick_wins.append(f"Flag at {url}: {f}")
        elif filename_is_interesting(Path(rel_path).name):
            out(f"    [i] Interesting file accessible (200 OK): {url}", "cyan")
            ctx.quick_wins.append(f"Accessible file worth reading by hand: {url} (saved: {save_path})")
    return fetched


def add_web_result(ctx: ScanContext, result: dict) -> None:
    ctx.web_results = [item for item in ctx.web_results if item['base_url'] != result['base_url']]
    ctx.web_results.append(result)
    merge_findings(ctx, result.get('findings', []))
    ctx.analysis_warnings.extend(w for w in result.get('warnings', []) if w not in ctx.analysis_warnings)


def new_web_mapper(ctx: ScanContext, url: str) -> WebMapper:
    identity = hashlib.sha256(url.encode()).hexdigest()[:12]
    return WebMapper(url, ctx.output_dir / 'web' / identity,
                     max_requests=ctx.web_pages, max_depth=ctx.web_depth,
                     seconds=ctx.web_seconds, delay=ctx.web_delay,
                     prefixes=ctx.flag_prefixes, include_hashes=ctx.include_hashes)


def load_web_results(ctx: ScanContext) -> None:
    for path in (ctx.output_dir / 'web').glob('*/crawl.json'):
        try:
            result = json.loads(path.read_text(encoding='utf-8'))
            if isinstance(result, dict) and isinstance(result.get('base_url'), str):
                add_web_result(ctx, result)
        except (OSError, ValueError, KeyError, TypeError):
            ctx.analysis_warnings.append(f'Could not load web evidence: {path}')


def phase_http_enum(ctx: ScanContext, port: OpenPort, tool_status: dict[str, bool], thorough: bool,
                     wordlist_override: Optional[str] = None, dirb_timeout: int = 300,
                     nikto_timeout: int = 150, vhost: bool = False,
                     vhost_domain: Optional[str] = None, vhost_wordlist: Optional[str] = None) -> bool:
    scheme = "https" if port.port in (443, 8443) or port.service in ("ssl/http", "https") else "http"
    web_target = f"[{ctx.target}]" if ":" in ctx.target else ctx.target
    base_url = f"{scheme}://{web_target}:{port.port}/"
    out(f"\n  [HTTP] Enumerating {base_url}", "cyan", bold=True)
    http_out_dir = ctx.output_dir / "http"

    # 0. nmap's port-based http/https guess is itself just a guess (443/8443
    #    -> https, everything else -> http). Before trusting it, confirm the
    #    port actually answers *some* real HTTP response — on the guessed
    #    scheme, or the other one. This is the direct fix for "confident but
    #    wrong": a custom protocol nmap labeled 'http' with no '?' will fail
    #    this probe outright, and a plain-HTTP service on a 443-style port
    #    (or vice versa) gets auto-corrected instead of silently enumerated
    #    against the wrong scheme.
    probe_ok = safe_fetch(base_url) is not None
    if not probe_ok:
        alt_scheme = "https" if scheme == "http" else "http"
        alt_url = f"{alt_scheme}://{web_target}:{port.port}/"
        if safe_fetch(alt_url) is not None:
            out(f"    [!] No response over {scheme}, but {alt_scheme} works — nmap's "
                f"{scheme}/{alt_scheme} guess (based on port number) was backwards. "
                f"Switching to {alt_scheme}.", "yellow", bold=True)
            ctx.quick_wins.append(f"Port {port.port}: actually {alt_scheme.upper()}, not "
                                   f"{scheme.upper()} as nmap's port-based guess assumed — "
                                   f"auto-corrected for this scan.")
            scheme = alt_scheme
            base_url = alt_url
        else:
            out(f"    [!] No HTTP response at all on http or https — nmap called this "
                f"'{port.service}' but it may not really be a web service. Skipping "
                f"HTTP-specific enumeration for this port.", "red", bold=True)
            ctx.recommendations.append(
                f"Port {port.port}/{port.protocol}: nmap reported '{port.service}' but neither "
                f"a plain HTTP nor HTTPS GET got any response — likely a misidentified custom "
                f"service. Verify manually: nc -nv {ctx.target} {port.port}  or  "
                f"openssl s_client -connect {ctx.target}:{port.port}"
            )
            ctx.quick_wins.append(f"Port {port.port}: labeled '{port.service}' by nmap but did "
                                   f"NOT respond to HTTP at all — verify by hand before trusting "
                                   f"that label.")
            return False  # nothing more useful to do against a non-HTTP port

    # Tracks whether every sub-step below actually finished (rc==0) rather
    # than hitting its timeout — gates whether --resume can trust this port
    # as fully enumerated. A partial gobuster/nikto/vhost run must NOT be
    # silently treated as complete on a later --resume.
    phase_complete = True

    mapper = None
    if ctx.crawl_enabled:
        out(f"    Mapping web evidence (up to {ctx.web_pages} requests / {ctx.web_seconds}s)...", "bright_black")
        mapper = new_web_mapper(ctx, base_url)
        try:
            mapper.run()
        finally:
            add_web_result(ctx, vars(mapper.result))
        phase_complete = phase_complete and mapper.result.complete
        out(f"    Web map: {len(mapper.result.pages)} pages, {len(mapper.result.leads)} leads.", "green")
    else:
        fetched = auto_fetch_and_scan(ctx, base_url, COMMON_CTF_PATHS, http_out_dir)
        disclosed_paths = []
        for rel_path, text in fetched:
            if rel_path.rstrip("/").endswith("robots.txt"):
                disclosed_paths += extract_robots_paths(text)
            elif rel_path.rstrip("/").endswith("sitemap.xml"):
                disclosed_paths += extract_sitemap_paths(text)
        if disclosed_paths:
            auto_fetch_and_scan(ctx, base_url, disclosed_paths, http_out_dir)

    # 2. Directory brute-force with gobuster/ffuf, extensions included.
    wordlist = find_wordlist(thorough=thorough, override=wordlist_override)
    discovered_paths: list[str] = []
    if wordlist_override and not wordlist:
        out(f"    --wordlist path not found: {wordlist_override}", "red")
    if not wordlist:
        out("    No dir-busting wordlist found. Checked:", "yellow")
        for c in WORDLIST_CANDIDATES:
            out(f"      {c}", "yellow")
        out("    Install with: sudo apt install dirb   (or install seclists)", "yellow")
    elif tool_status.get("gobuster"):
        log_path = http_out_dir / f"gobuster_{port.port}.txt"
        cmd = [
            "gobuster", "dir",
            "-u", base_url,
            "-w", wordlist,
            "-x", CTF_EXTENSIONS,
            "-q",
            "-k",  # skip TLS verification, common on CTF self-signed certs
            "--no-color",  # gobuster emits color codes even when piped in some versions —
                            # ANSI_ESCAPE_RE strip below is defense-in-depth, this is the real fix
        ]
        rc, gb_output = spinner_run(f"gobuster dir-busting port {port.port} (with extensions)...",
                                     cmd, log_path, timeout=dirb_timeout)
        out(f"    gobuster log: {log_path}", "green")
        if rc == 124:
            out(f"    [!] gobuster hit its {dirb_timeout}s timeout — results may be incomplete.",
                "yellow", bold=True)
            ctx.recommendations.append(
                f"Port {port.port}: gobuster timed out after {dirb_timeout}s — re-run with a "
                f"higher --dirb-timeout, or a smaller wordlist, to get a complete listing."
            )
            phase_complete = False
        if rc != 0:
            phase_complete = False
        discovered_paths = parse_gobuster_paths(gb_output)
    elif tool_status.get("ffuf"):
        log_path = http_out_dir / f"ffuf_{port.port}.txt"
        cmd = [
            "ffuf", "-ac",
            "-u", f"{base_url}FUZZ",
            "-w", wordlist,
            "-e", "." + ",.".join(CTF_EXTENSIONS.split(",")),
            "-of", "csv",
            "-o", str(log_path.with_suffix(".csv")),
            "-s",
        ]
        rc, _ = spinner_run(f"ffuf dir-busting port {port.port} (with extensions)...",
                             cmd, log_path, timeout=dirb_timeout)
        out(f"    ffuf log: {log_path.with_suffix('.csv')}", "green")
        if rc == 124:
            out(f"    [!] ffuf hit its {dirb_timeout}s timeout — results may be incomplete.",
                "yellow", bold=True)
            ctx.recommendations.append(
                f"Port {port.port}: ffuf timed out after {dirb_timeout}s — re-run with a "
                f"higher --dirb-timeout, or a smaller wordlist, to get a complete listing."
            )
            phase_complete = False
        if rc != 0:
            phase_complete = False
        csv_path = log_path.with_suffix(".csv")
        if csv_path.exists():
            discovered_paths = parse_ffuf_csv_paths(csv_path.read_text(errors="replace"))
    else:
        out("    Neither gobuster nor ffuf available — skipping dir-busting.", "yellow")

    if discovered_paths:
        preview = discovered_paths[:8]
        out(f"    Found {len(discovered_paths)} path(s): {', '.join(preview)}"
            f"{' ...' if len(discovered_paths) > len(preview) else ''}", "green")
        out(f"    Auto-fetching {min(len(discovered_paths), MAX_AUTO_FETCHED_PATHS)} "
            f"discovered 200-OK path(s) and scanning for flags...", "bright_black")
        if mapper:
            try:
                mapper.run(discovered_paths)
            finally:
                add_web_result(ctx, vars(mapper.result))
            phase_complete = phase_complete and mapper.result.complete
        else:
            auto_fetch_and_scan(ctx, base_url, discovered_paths, http_out_dir)

    # 3. nikto for known web-server vulnerabilities.
    if tool_status.get("nikto"):
        log_path = http_out_dir / f"nikto_{port.port}.txt"
        cmd = ["nikto", "-h", base_url, "-nointeractive"]
        rc, nikto_output = spinner_run(f"nikto scanning port {port.port}...", cmd, log_path,
                                        timeout=nikto_timeout)
        out(f"    nikto log: {log_path}", "green")
        if rc == 124:
            out(f"    [!] nikto hit its {nikto_timeout}s timeout — results may be incomplete.",
                "yellow", bold=True)
            ctx.recommendations.append(
                f"Port {port.port}: nikto timed out after {nikto_timeout}s — re-run with a "
                f"higher --nikto-timeout if you have time to spare."
            )
            phase_complete = False
        elif rc != 0:
            phase_complete = False
        else:
            findings = [ln.strip() for ln in nikto_output.splitlines() if ln.strip().startswith("+")
                        and "Target" not in ln and "Start Time" not in ln and "Server:" not in ln]
            if findings:
                out(f"    nikto flagged {len(findings)} item(s), e.g.:", "green")
                for ln in findings[:5]:
                    out(f"      {ln}", "bright_black")
    else:
        out("    nikto not available — skipping web vuln scan.", "yellow")

    # 4. Optional vhost fuzzing — common on CTF boxes that route by Host header.
    if vhost:
        if not phase_vhost_fuzz(ctx, port, tool_status, vhost_domain, vhost_wordlist, dirb_timeout):
            phase_complete = False

    ctx.recommendations.append(
        f"HTTP port {port.port} open -> manually check {base_url}robots.txt, "
        f"view page source, check for /admin, /login, comments in HTML."
    )

    if phase_complete:
        mark_done(http_out_dir / f"http_{port.port}.done")
    else:
        out(f"    (One or more sub-steps timed out — not marking port {port.port} HTTP "
            f"enumeration complete; --resume will re-run it.)", "bright_black")
    return True


# Small built-in list used for --vhost fuzzing when no wordlist is supplied —
# covers the subdomain names that show up constantly on HTB/THM boxes.
DEFAULT_VHOST_WORDS = [
    "www", "admin", "dev", "test", "staging", "api", "beta", "portal",
    "blog", "shop", "mail", "webmail", "vpn", "intranet", "internal",
    "app", "dashboard", "monitor", "backup", "old", "new", "secure",
    "support", "help", "cloud", "git", "ci", "jenkins", "grafana",
]


def phase_vhost_fuzz(ctx: ScanContext, port: OpenPort, tool_status: dict[str, bool],
                      vhost_domain: Optional[str], vhost_wordlist: Optional[str],
                      timeout: int) -> bool:
    """Returns False if this sub-phase hit its timeout (results possibly
    incomplete), True otherwise — used by phase_http_enum to decide whether
    the whole HTTP phase can be marked --resume-complete."""
    domain = vhost_domain or (ctx.target if is_valid_hostname(ctx.target) and not is_valid_ip(ctx.target) else None)
    if not domain:
        out("    --vhost requested but no hostname to fuzz against — pass --vhost-domain "
            "(e.g. --vhost-domain target.htb).", "yellow")
        ctx.recommendations.append(
            "Vhost fuzzing skipped: target is a bare IP with no --vhost-domain given. "
            "If you find a hostname (e.g. in a TLS cert or an /etc/hosts hint), re-run with "
            "--vhost --vhost-domain <that hostname>."
        )
        return True

    out(f"\n  [VHOST] Fuzzing subdomains of {domain} via Host header on port {port.port}", "cyan", bold=True)
    scheme = "https" if port.port in (443, 8443) or port.service in ("ssl/http", "https") else "http"
    web_target = f"[{ctx.target}]" if ":" in ctx.target else ctx.target
    base_url = f"{scheme}://{web_target}:{port.port}/"
    out_dir = ctx.output_dir / "http"

    if tool_status.get("gobuster"):
        wl = vhost_wordlist or find_wordlist(thorough=False)
        if not wl:
            # gobuster vhost mode needs a real wordlist file — write our small default one out
            wl_path = ctx.output_dir / "http" / "vhost_wordlist.txt"
            wl_path.parent.mkdir(parents=True, exist_ok=True)
            wl_path.write_text("\n".join(DEFAULT_VHOST_WORDS))
            wl = str(wl_path)
        log_path = out_dir / f"vhost_{port.port}.txt"
        cmd = [
            "gobuster", "vhost",
            "-u", base_url,
            "-w", wl,
            "--append-domain",
            "-q", "-k", "--no-color",
        ]
        rc, vh_output = spinner_run(f"gobuster vhost fuzzing on port {port.port}...",
                                     cmd, log_path, timeout=timeout)
        out(f"    vhost log: {log_path}", "green")
        if rc == 124:
            out(f"    [!] vhost fuzzing hit its {timeout}s timeout — results may be incomplete.",
                "yellow", bold=True)
            ctx.recommendations.append(
                f"Port {port.port}: vhost fuzzing timed out after {timeout}s — re-run with a "
                f"higher --dirb-timeout to finish the wordlist."
            )
            return False
        found_vhosts = [ANSI_ESCAPE_RE.sub("", ln).strip() for ln in vh_output.splitlines() if "Found:" in ln]
        if found_vhosts:
            out(f"    Found {len(found_vhosts)} vhost(s):", "green", bold=True)
            for v in found_vhosts[:8]:
                out(f"      {v}", "green")
            ctx.quick_wins.append(f"Port {port.port}: vhost fuzzing found {len(found_vhosts)} "
                                   f"virtual host(s) — see {log_path}. Add them to /etc/hosts "
                                   f"and re-scan — they often serve completely different content.")
        else:
            out("    No additional vhosts found with this wordlist.", "yellow")
    else:
        out("    gobuster not available for vhost mode — skipping. (ffuf-based vhost fuzzing "
            "isn't wired up automatically; run it by hand: "
            f"ffuf -u {base_url} -H 'Host: FUZZ.{domain}' -w <wordlist> -fs <baseline size>)",
            "yellow")
    return True


def parse_smb_shares(output: str) -> list[str]:
    shares = []
    skip = {"admin$", "c$", "ipc$", "print$"}
    for line in output.splitlines():
        m = re.match(r"^\s*(\S+)\s+(Disk|IPC|Printer)\b", line)
        if m and m.group(2) == "Disk" and m.group(1).lower() not in skip:
            shares.append(m.group(1))
    return shares


# --------------------------------------------------------------------------
# NSE (nmap scripting engine) output parsing — shared by phase_windows_ad_enum.
# nmap's -oN text format nests a script's output under a "| script-name:"
# header, with continuation lines prefixed "|   " and the final line of a
# block prefixed "|_  ". These helpers strip that prefix so plain "Label:
# value" extraction works regardless of which script produced the line —
# which also means fields already collected by -sC's default-category
# scripts (smb-os-discovery, smb2-security-mode, rdp-ntlm-info all run by
# default) get surfaced from the existing deep-scan log for free, with zero
# extra scan time, instead of being silently discarded the way they were
# before this only flag-scanned the raw text.
# --------------------------------------------------------------------------

def _clean_nse_lines(text: str) -> list[str]:
    return [re.sub(r"^\|[_]?\s*", "", line) for line in text.splitlines()]


def extract_nse_field(text: str, label: str) -> Optional[str]:
    """First 'label: value' match (case-insensitive) after stripping NSE
    line prefixes. Returns None if the label never appears."""
    pattern = re.compile(rf"^\s*{re.escape(label)}:\s*(.+?)\s*$", re.IGNORECASE)
    for line in _clean_nse_lines(text):
        m = pattern.match(line)
        if m:
            return m.group(1).strip()
    return None


def phase_smb_loot(ctx: ScanContext, share: str) -> bool:
    """Attempt to anonymously download files from an SMB share and flag-scan
    them. Returns False if the download hit its timeout (loot may be
    incomplete) so the caller can decide whether --resume should trust it."""
    if share in {"", ".", ".."} or any(c in share for c in "/\\\r\n"):
        ctx.analysis_warnings.append(f"Skipped unsafe SMB share name: {share!r}")
        return False
    loot_dir = ctx.output_dir / "loot" / "smb" / share
    loot_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "smbclient", f"//{ctx.target}/{share}", "-N",
        "-c", "prompt OFF; recurse ON; mget *",
    ]
    log_path = ctx.output_dir / "smb" / f"download_{share}.txt"
    rc, _ = spinner_run(f"Downloading files from share '{share}'...", cmd, log_path,
                         timeout=120, cwd=loot_dir)

    downloaded = list(loot_dir.rglob("*"))
    files_only = [f for f in downloaded if f.is_file()]
    if not files_only:
        out(f"    No files downloaded from '{share}' (empty or access issue).", "yellow")
        return rc == 0

    out(f"    Downloaded {len(files_only)} file(s) from '{share}' -> {loot_dir}", "green")
    if rc == 124:
        out(f"    [!] Download timed out — '{share}' may have more files than what's here.",
            "yellow", bold=True)
        ctx.recommendations.append(
            f"SMB share '{share}' download timed out after 120s — likely incomplete, "
            f"re-run to get the rest (or download manually: smbclient //{ctx.target}/{share} -N)."
        )
    for f in files_only:
        if filename_is_interesting(f.name):
            out(f"    [i] Interesting filename: {f}", "cyan")
            ctx.quick_wins.append(f"Interesting SMB file downloaded: {f}")
        try:
            if f.stat().st_size <= MAX_LOOT_FILE_BYTES:
                content = f.read_text(errors="replace")
                new_flags = record_flags(ctx, content, f"SMB share '{share}' file {f.name}")
                for flag in new_flags:
                    out(f"    [!] FLAG CANDIDATE in {f}: {flag}", "magenta", bold=True)
                    ctx.quick_wins.append(f"Flag in SMB file {f}: {flag}")
        except (UnicodeDecodeError, OSError):
            pass  # binary file — not flag-scannable as text, still downloaded for manual review
    return rc == 0


def phase_smb_enum(ctx: ScanContext, port: OpenPort, tool_status: dict[str, bool]) -> None:
    out(f"\n  [SMB] Checking anonymous access on port {port.port}", "cyan", bold=True)
    if not tool_status.get("smbclient"):
        out("    smbclient not available — skipping.", "yellow")
        ctx.recommendations.append(
            f"SMB port {port.port} open -> install smbclient and test anonymous "
            f"login manually: smbclient -L //{ctx.target}/ -N"
        )
        return

    phase_complete = True
    log_path = ctx.output_dir / "smb" / "anon_list_shares.txt"
    cmd = ["smbclient", "-L", f"//{ctx.target}/", "-N"]  # -N = no password
    rc, output = spinner_run("Listing SMB shares anonymously...", cmd, log_path, timeout=60)
    if rc == 124:
        phase_complete = False
        ctx.recommendations.append(
            f"SMB port {port.port}: share listing timed out after 60s — re-run to confirm "
            f"what's actually there before trusting an empty result."
        )

    if "NT_STATUS_ACCESS_DENIED" in output or "NT_STATUS_LOGON_FAILURE" in output:
        out("    Anonymous access denied.", "yellow")
    else:
        shares = parse_smb_shares(output)
        if shares:
            out(f"    Anonymous SMB listing succeeded! Shares: {', '.join(shares)}", "green", bold=True)
            ctx.quick_wins.append(f"SMB port {port.port}: anonymous listing succeeded, "
                                   f"shares = {', '.join(shares)}")
            for share in shares:
                if not phase_smb_loot(ctx, share):
                    phase_complete = False
        else:
            out("    Anonymous listing worked but found no browsable (Disk) shares.", "yellow")

    ctx.recommendations.append(
        f"SMB port {port.port} open -> also try enum4linux-ng and check for "
        f"null session / guest access, and smbmap."
    )

    if phase_complete:
        mark_done(ctx.output_dir / "smb" / f"smb_{port.port}.done")
    else:
        out(f"    (A sub-step timed out — not marking port {port.port} SMB enumeration "
            f"complete; --resume will re-run it.)", "bright_black")


def _ftp_walk(ftp: ftplib.FTP, remote_dir: str, loot_dir: Path, ctx: ScanContext,
              depth: int = 0, max_depth: int = 3, max_files: int = 200) -> int:
    """Recursively mirror an anonymous FTP tree into loot_dir, flag-scanning
    every downloaded file. Returns number of files downloaded."""
    if depth > max_depth:
        return 0
    downloaded = 0
    try:
        entries = list(ftp.mlsd(remote_dir or "."))
    except Exception:
        # server doesn't support MLSD — fall back to NLST (no type info,
        # so we just try RETR and treat failures as "probably a directory")
        try:
            names = ftp.nlst(remote_dir or "")
        except Exception:
            return 0
        entries = [(n, {"type": "file"}) for n in names]

    for name, facts in entries:
        if name in (".", ".."):
            continue
        if downloaded >= max_files:
            break
        remote_path = f"{remote_dir}/{name}".lstrip("/") if remote_dir else name
        if "\r" in remote_path or "\n" in remote_path or "\\" in remote_path:
            continue
        candidate_path = (loot_dir / remote_path).resolve()
        if not candidate_path.is_relative_to(loot_dir.resolve()):
            ctx.analysis_warnings.append(f"Skipped escaping FTP path: {remote_path}")
            continue
        entry_type = facts.get("type", "file")

        if entry_type == "dir":
            local_subdir = loot_dir / remote_path
            local_subdir.mkdir(parents=True, exist_ok=True)
            downloaded += _ftp_walk(ftp, remote_path, loot_dir, ctx, depth + 1, max_depth, max_files - downloaded)
            continue

        try:
            size = ftp.size(remote_path)
        except Exception:
            size = None
        if size is not None and size > MAX_LOOT_FILE_BYTES:
            continue  # skip huge files

        local_path = loot_dir / remote_path
        local_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            buf = io.BytesIO()
            def limited_write(chunk):
                if buf.tell() + len(chunk) > MAX_LOOT_FILE_BYTES:
                    raise ValueError("FTP file exceeds download limit")
                buf.write(chunk)
            ftp.retrbinary(f"RETR {remote_path}", limited_write)
            data = buf.getvalue()
            local_path.write_bytes(data)
            downloaded += 1

            if filename_is_interesting(name):
                out(f"    [i] Interesting filename: {remote_path}", "cyan")
                ctx.quick_wins.append(f"Interesting FTP file downloaded: {local_path}")

            try:
                text = data.decode("utf-8", errors="replace")
                new_flags = record_flags(ctx, text, f"FTP file {remote_path}")
                for flag in new_flags:
                    out(f"    [!] FLAG CANDIDATE in {remote_path}: {flag}", "magenta", bold=True)
                    ctx.quick_wins.append(f"Flag in FTP file {remote_path}: {flag}")
            except Exception:
                pass
        except Exception:
            continue

    return downloaded


def phase_ftp_enum(ctx: ScanContext, port: OpenPort) -> None:
    """Anonymous FTP check using Python's built-in ftplib — no external
    'ftp' client binary required, and no ambiguous response-code parsing."""
    out(f"\n  [FTP] Checking anonymous login on port {port.port}", "cyan", bold=True)
    loot_dir = ctx.output_dir / "loot" / "ftp"
    log_path = ctx.output_dir / "ftp" / "anon_login.txt"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    phase_complete = True
    log_lines = [f"Connecting to {ctx.target}:{port.port} ..."]
    try:
        ftp = ftplib.FTP(timeout=15)
        ftp.connect(ctx.target, port.port)
        welcome = ftp.getwelcome()
        log_lines.append(f"Welcome: {welcome}")

        ftp.login()  # anonymous / anonymous@ by default
        log_lines.append("Login: SUCCESS (anonymous)")
        out("    Anonymous FTP login SUCCEEDED!", "green", bold=True)
        ctx.quick_wins.append(f"FTP port {port.port}: anonymous login SUCCEEDED. "
                               f"Downloading and flag-scanning accessible files...")

        try:
            listing = "\n".join(ftp.nlst())
            log_lines.append("Root listing:\n" + listing)
        except Exception:
            pass

        downloaded = _ftp_walk(ftp, "", loot_dir, ctx)
        log_lines.append(f"\nDownloaded {downloaded} file(s) into {loot_dir}")
        out(f"    Downloaded {downloaded} file(s) -> {loot_dir}", "green")

        try:
            ftp.quit()
        except Exception:
            pass

        ctx.recommendations.append(
            f"FTP port {port.port} -> anonymous login SUCCEEDED. Loot saved to "
            f"{loot_dir} ({downloaded} file(s)); browse it by hand too."
        )

    except ftplib.error_perm as e:
        # A clean login rejection is a complete, trustworthy result — not
        # a failure of the check itself.
        log_lines.append(f"Login: REJECTED ({e})")
        out("    Anonymous login rejected.", "yellow")
        ctx.recommendations.append(
            f"FTP port {port.port} open -> anonymous login rejected; try known/weak creds, "
            f"or check the banner ({port.version}) for a known CVE."
        )
    except Exception as e:
        # Anything else (connection reset, the 15s ftplib timeout expiring
        # mid-walk, etc.) means the loot download may have stopped partway
        # through — do NOT mark this port done, or --resume would trust a
        # partial download the same way a truncated gobuster log would be.
        log_lines.append(f"Connection error: {e}")
        out(f"    Could not complete FTP check: {e}", "yellow")
        ctx.recommendations.append(
            f"FTP port {port.port} open -> automatic check failed ({e}); verify manually."
        )
        phase_complete = False

    log_path.write_text("\n".join(log_lines))
    if phase_complete:
        mark_done(ctx.output_dir / "ftp" / f"ftp_{port.port}.done")
    else:
        out(f"    (Check didn't finish cleanly — not marking port {port.port} FTP "
            f"enumeration complete; --resume will re-run it.)", "bright_black")


# ==========================================================================
# Phase 3b — Windows / Active Directory enumeration
# ==========================================================================
# Triggers automatically whenever a Kerberos/RPC/SMB/LDAP/RDP/WinRM port is
# open — a "hard" CTF box is very often a Windows or AD target, and that
# needs a genuinely different playbook than the Linux/web one above:
# domain/OS fingerprinting, SMB signing (relay potential), MS17-010
# (EternalBlue), anonymous RPC/null-session user enumeration, and correctly
# recognizing WinRM instead of wasting a dirb run against its generic
# 'Microsoft HTTPAPI httpd' banner.

def phase_windows_ad_enum(ctx: ScanContext, tool_status: dict[str, bool],
                           timeout: int = 180, resume: bool = False) -> None:
    relevant_ports = [p for p in ctx.open_ports if p.port in WINDOWS_TRIGGER_PORTS]
    if not relevant_ports:
        return

    win_out_dir = ctx.output_dir / "windows"
    marker = win_out_dir / "windows.done"
    if resume and phase_is_done(marker):
        out(f"  [resume] Windows/AD enumeration already complete (found {marker}) — skipping.",
            "blue")
        return

    section("Phase 3b — Windows / Active Directory Enumeration")
    phase_complete = True
    smb_ports_open = [p.port for p in ctx.open_ports if p.port in SMB_RELATED_PORTS]

    # 1. Surface fields -sC's DEFAULT-category scripts already collected
    #    (smb-os-discovery, smb2-security-mode, rdp-ntlm-info are all
    #    default+safe) but which were previously discarded — this costs
    #    zero extra scan time, it's pure parsing of what Phase 2 already ran.
    deep_scan_log = ctx.output_dir / "nmap" / "deep_scan.nmap"
    existing_text = deep_scan_log.read_text(errors="replace") if deep_scan_log.exists() else ""

    os_str = extract_nse_field(existing_text, "OS")
    computer = extract_nse_field(existing_text, "Computer name")
    domain = extract_nse_field(existing_text, "Domain name")
    forest = extract_nse_field(existing_text, "Forest name")
    fqdn = extract_nse_field(existing_text, "FQDN")
    if os_str or computer or domain:
        parts = []
        if os_str:
            parts.append(f"OS={os_str}")
        if computer:
            parts.append(f"Computer={computer}")
        if domain:
            parts.append(f"Domain={domain}")
        if forest and forest != domain:
            parts.append(f"Forest={forest}")
        if fqdn:
            parts.append(f"FQDN={fqdn}")
        msg = "Windows host fingerprint (SMB): " + ", ".join(parts)
        out(f"    {msg}", "green", bold=True)
        ctx.quick_wins.append(msg)
        if os_str and tool_status.get("searchsploit"):
            searchsploit_lookup(ctx, OpenPort(port=445, service="smb-os", version=os_str), tool_status)

    sign_line = next((ln for ln in _clean_nse_lines(existing_text)
                       if "message signing" in ln.lower()), None)
    if sign_line:
        risky = "not required" in sign_line.lower() or "disabled" in sign_line.lower()
        out(f"    SMB signing: {sign_line}", "yellow" if risky else "green")
        if risky:
            ctx.quick_wins.append(
                f"SMB signing is NOT enforced ({sign_line}) — vulnerable to SMB relay "
                f"(ntlmrelayx). Worth it if you can coerce auth (PetitPotam, PrinterBug, "
                f"coercer) from another angle."
            )

    ntlm_fields = {}
    for label in ("Target_Name", "NetBIOS_Domain_Name", "NetBIOS_Computer_Name",
                  "DNS_Domain_Name", "DNS_Computer_Name", "DNS_Tree_Name", "Product_Version"):
        val = extract_nse_field(existing_text, label)
        if val:
            ntlm_fields[label] = val
    if ntlm_fields:
        msg = "RDP NTLM fingerprint: " + ", ".join(f"{k}={v}" for k, v in ntlm_fields.items())
        out(f"    {msg}", "green", bold=True)
        ctx.quick_wins.append(msg)

    # 2. Targeted scripts NOT in the default category: share/session
    #    enumeration and the MS17-010 (EternalBlue) safe-check.
    if smb_ports_open:
        port_list = ",".join(str(p) for p in smb_ports_open)
        log_path = win_out_dir / "smb_scripts.nmap"
        cmd = [
            "nmap", "-Pn", "-p", port_list,
            "--script", "smb-enum-shares,smb-enum-sessions,smb-vuln-ms17-010",
            "-oN", str(log_path), ctx.target,
        ]
        rc, output = spinner_run("Running targeted SMB enum/vuln scripts...", cmd, log_path,
                                  timeout=timeout)
        if rc == 124:
            phase_complete = False
            out(f"    [!] SMB script scan hit its {timeout}s timeout — results may be incomplete.",
                "yellow", bold=True)
            ctx.recommendations.append(
                f"SMB targeted script scan timed out after {timeout}s — re-run with a higher "
                f"--windows-timeout."
            )
        elif rc == 127:
            out("    nmap not installed — skipping.", "red")
        else:
            record_flags(ctx, output, "nmap SMB enum/vuln scripts")
            if re.search(r"state:\s*vulnerable", output, re.IGNORECASE):
                out("    [!!!] VULNERABLE TO MS17-010 (EternalBlue)!", "red", bold=True)
                ctx.quick_wins.append(
                    f"Port 445: VULNERABLE to MS17-010 (EternalBlue) — see {log_path}. Near-"
                    f"certain SYSTEM path: metasploit exploit/windows/smb/ms17_010_eternalblue, "
                    f"or a public standalone PoC."
                )
            nse_shares = [ln.strip() for ln in _clean_nse_lines(output)
                          if re.match(r"^[A-Za-z0-9_$.\- ]+\s+(Disk|IPC|Printer)\b", ln.strip())]
            if nse_shares:
                out(f"    Shares (via NSE enum): {'; '.join(nse_shares[:10])}", "green")
            out(f"    SMB scripts log: {log_path}", "green")

    # 3. rpcclient anonymous/null-session enumeration — often works even
    #    when smbclient -L share listing is denied, since it's a different
    #    RPC pipe (lsarpc/samr) rather than the file-sharing surface.
    if smb_ports_open and tool_status.get("rpcclient"):
        log_path = win_out_dir / "rpcclient_anon.txt"
        cmd = [
            "rpcclient", "-U", "", "-N", "-c",
            "srvinfo;enumdomusers;enumdomgroups;querydominfo;lsaquery", ctx.target,
        ]
        rc, output = spinner_run("rpcclient anonymous/null-session enumeration...",
                                  cmd, log_path, timeout=30)
        if rc == 124:
            phase_complete = False
            out("    [!] rpcclient timed out.", "yellow")
        else:
            record_flags(ctx, output, "rpcclient null session")
            if output.strip() and "NT_STATUS_ACCESS_DENIED" not in output and rc != 127:
                users = re.findall(r"user:\[(.*?)\]", output)
                if users:
                    out(f"    [!] Null-session RPC enumeration SUCCEEDED — {len(users)} "
                        f"user(s) found!", "magenta", bold=True)
                    shown = ", ".join(users[:20]) + ("..." if len(users) > 20 else "")
                    ctx.quick_wins.append(
                        f"rpcclient null session enumerated {len(users)} domain user(s): "
                        f"{shown} — gold for password spraying / AS-REP roasting. "
                        f"See {log_path}."
                    )
                else:
                    out("    rpcclient null session connected but returned no usable "
                        "enumeration data.", "yellow")
            elif rc == 127:
                pass  # tool missing, already noted in checklist
            else:
                out("    rpcclient null session denied (expected on a hardened box).", "yellow")

    # 4. enum4linux-ng, if installed — comprehensive bonus pass.
    if smb_ports_open and tool_status.get("enum4linux-ng"):
        log_path = win_out_dir / "enum4linux-ng.txt"
        cmd = ["enum4linux-ng", "-A", ctx.target]
        rc, output = spinner_run("enum4linux-ng full enumeration...", cmd, log_path,
                                  timeout=max(timeout, 180))
        if rc == 124:
            phase_complete = False
            out("    [!] enum4linux-ng hit its timeout — results may be incomplete.", "yellow")
        elif rc != 127:
            record_flags(ctx, output, "enum4linux-ng")
            out(f"    enum4linux-ng log: {log_path}", "green")

    # 5. RDP-specific script not in the default category (encryption/NLA level).
    rdp_open = [p.port for p in ctx.open_ports if p.port in RDP_PORTS]
    if rdp_open:
        log_path = win_out_dir / "rdp_scripts.nmap"
        cmd = ["nmap", "-Pn", "-p", "3389", "--script", "rdp-enum-encryption",
               "-oN", str(log_path), ctx.target]
        rc, output = spinner_run("Checking RDP encryption/NLA settings...", cmd, log_path,
                                  timeout=60)
        if rc == 124:
            phase_complete = False
        elif rc != 127:
            record_flags(ctx, output, "nmap rdp-enum-encryption")
            out(f"    RDP encryption scan log: {log_path}", "green")

    # 6. WinRM recognition — 'Microsoft HTTPAPI httpd' on 5985/5986 is
    #    WinRM's standard banner, not a real web app; running gobuster/nikto
    #    against it (which the HTTP phase would otherwise do, since these
    #    ports are in HTTP_PORTS) wastes the clock on a dead end.
    winrm_open = [p for p in ctx.open_ports if p.port in WINRM_PORTS]
    if winrm_open:
        ports_str = "/".join(str(p.port) for p in winrm_open)
        out(f"    Port(s) {ports_str}: this is WinRM, not a real web app — "
            f"gobuster/nikto against it won't find anything.", "cyan", bold=True)
        ctx.quick_wins.append(
            f"Port(s) {ports_str}: WinRM is enabled. Once you have ANY valid creds "
            f"(even low-priv/service account): evil-winrm -i {ctx.target} -u USER -p PASS "
            f"or netexec winrm {ctx.target} -u USER -p PASS. Try spraying creds found "
            f"elsewhere (SMB shares, a web app, etc.) here first — WinRM access is "
            f"usually an instant shell."
        )

    # 7. Name unknown dynamic RPC ports instead of leaving them as dead ends —
    #    this is exactly the 'port 49670/53559 unknown' situation from a
    #    real run against this tool.
    unknown_high_ports = [
        p for p in ctx.open_ports
        if p.port in WINDOWS_DYNAMIC_RPC_RANGE and p.service.strip("?").lower() in ("unknown", "msrpc", "")
    ]
    if unknown_high_ports and (RPC_PORT in [p.port for p in ctx.open_ports] or smb_ports_open):
        for p in unknown_high_ports[:5]:  # cap — these are slow one-port-at-a-time scans
            log_path = win_out_dir / f"msrpc_enum_{p.port}.nmap"
            cmd = ["nmap", "-Pn", "-p", str(p.port), "--script", "msrpc-enum",
                   "-oN", str(log_path), ctx.target]
            rc, output = spinner_run(f"Identifying RPC service on port {p.port}...",
                                      cmd, log_path, timeout=30)
            if rc == 124:
                phase_complete = False
                continue
            if rc == 127:
                break
            record_flags(ctx, output, f"msrpc-enum port {p.port}")
            interface_lines = [ln.strip() for ln in output.splitlines()
                                if re.search(r"uuid|interface", ln, re.IGNORECASE) and "nmap" not in ln.lower()]
            if interface_lines:
                out(f"    Port {p.port} RPC interface(s): {'; '.join(interface_lines[:3])}", "green")
                ctx.quick_wins.append(f"Port {p.port}: named via msrpc-enum — see {log_path}")

    if phase_complete:
        mark_done(marker)
    else:
        out("    (A sub-step timed out — not marking Windows/AD enumeration complete; "
            "--resume will re-run it.)", "bright_black")


def phase_service_enum(ctx: ScanContext, tool_status: dict[str, bool], thorough: bool,
                        wordlist_override: Optional[str] = None, dirb_timeout: int = 300,
                        nikto_timeout: int = 150, vhost: bool = False,
                        vhost_domain: Optional[str] = None, vhost_wordlist: Optional[str] = None,
                        resume: bool = False, no_windows: bool = False,
                        windows_timeout: int = 180) -> None:
    section("Phase 3 — Service-Specific Enumeration")
    if not ctx.open_ports:
        out("  Skipped — no open ports to enumerate.", "yellow")
        return

    matched_any = False
    for p in ctx.open_ports:
        if _matches(p, HTTP_PORTS, HTTP_SERVICE_NAMES):
            marker = ctx.output_dir / "http" / f"http_{p.port}.done"
            if resume and phase_is_done(marker):
                out(f"  [resume] HTTP port {p.port} already fully enumerated "
                    f"(found {marker}) — skipping.", "blue")
            else:
                if resume and (ctx.output_dir / "http" / f"gobuster_{p.port}.txt").exists():
                    out(f"  [resume] HTTP port {p.port} has a log but no completion "
                        f"marker — it looks incomplete (timed out or interrupted). "
                        f"Re-running rather than trusting a partial result.", "yellow")
                phase_http_enum(ctx, p, tool_status, thorough, wordlist_override, dirb_timeout,
                                 nikto_timeout, vhost, vhost_domain, vhost_wordlist)
            matched_any = True
        if _matches(p, SMB_PORTS, SMB_SERVICE_NAMES):
            marker = ctx.output_dir / "smb" / f"smb_{p.port}.done"
            if resume and phase_is_done(marker):
                out(f"  [resume] SMB port {p.port} already fully enumerated "
                    f"(found {marker}) — skipping.", "blue")
            else:
                if resume and (ctx.output_dir / "smb" / "anon_list_shares.txt").exists():
                    out(f"  [resume] SMB port {p.port} has a log but no completion "
                        f"marker — re-running rather than trusting a partial result.", "yellow")
                phase_smb_enum(ctx, p, tool_status)
            matched_any = True
        if _matches(p, FTP_PORTS, FTP_SERVICE_NAMES):
            marker = ctx.output_dir / "ftp" / f"ftp_{p.port}.done"
            if resume and phase_is_done(marker):
                out(f"  [resume] FTP port {p.port} already fully enumerated "
                    f"(found {marker}) — skipping.", "blue")
            else:
                if resume and (ctx.output_dir / "ftp" / "anon_login.txt").exists():
                    out(f"  [resume] FTP port {p.port} has a log but no completion "
                        f"marker — re-running rather than trusting a partial result.", "yellow")
                phase_ftp_enum(ctx, p)
            matched_any = True

    if not matched_any:
        out("  No HTTP/SMB/FTP ports among open ports — nothing to auto-enumerate here.", "yellow")

    if not no_windows:
        phase_windows_ad_enum(ctx, tool_status, timeout=windows_timeout, resume=resume)


# ==========================================================================
# Recommendation engine (general, port-driven)
# ==========================================================================

GENERAL_TIPS = {
    21: "FTP (21) open -> test anonymous login; check for writable dirs; banner-grab version for known CVEs.",
    22: "SSH (22) open -> banner-grab version; check for weak/reused creds; rarely the initial foothold in CTF.",
    23: "Telnet (23) open -> often misconfigured/legacy; try default creds.",
    25: "SMTP (25) open -> try VRFY/EXPN user enumeration; check for open relay.",
    53: "DNS (53) open -> try zone transfer: dig axfr @<target> <domain>.",
    69: "TFTP (69/udp) open -> no auth by default; try tftp <target> to GET/PUT files.",
    80: "HTTP (80) open -> inspect page source, check /robots.txt, /sitemap.xml, HTTP headers.",
    110: "POP3 (110) open -> banner-grab; check for cleartext creds if paired with another service.",
    111: "RPCbind (111) open -> run rpcinfo -p <target>; often pairs with NFS.",
    123: "NTP (123/udp) open -> check for monlist amplification / info leak (older ntpd).",
    139: "SMB (139) open -> test anonymous/null sessions; try enum4linux-ng.",
    143: "IMAP (143) open -> banner-grab; check auth mechanisms.",
    161: "SNMP (161/udp) open -> try public community string: snmpwalk -c public -v1 <target>.",
    443: "HTTPS (443) open -> check TLS cert for subject/SAN hostnames; inspect page source.",
    445: "SMB (445) open -> test anonymous/null sessions; try enum4linux-ng, smbmap, crackmapexec.",
    2049: "NFS (2049) open -> showmount -e <target> to list exports.",
    3306: "MySQL (3306) open -> try default/weak creds; check for anonymous access.",
    3389: "RDP (3389) open -> check for BlueKeep-class CVEs; rarely the initial foothold in CTF.",
    5432: "PostgreSQL (5432) open -> try default creds (postgres/postgres); check for trust auth.",
    6379: "Redis (6379) open -> often unauthenticated by default; try redis-cli -h <target>.",
    8080: "HTTP-alt (8080) open -> same as port 80; check for exposed admin panels (Tomcat, Jenkins).",
}


def build_recommendations(ctx: ScanContext) -> None:
    for p in ctx.open_ports:
        tip = GENERAL_TIPS.get(p.port)
        if tip and tip not in ctx.recommendations:
            ctx.recommendations.append(tip)


def flag_low_confidence_fingerprints(ctx: ScanContext) -> None:
    """nmap's -sV is a guess, not a certainty, and it fails in two different
    directions:
      1. Empty/generic — an unrecognized custom service reports as blank or
         'tcpwrapped'. Auto-enumeration above obviously won't fire for this.
      2. Confident-looking but unconfirmed — nmap falls back to a port-based
         guess and marks it with a trailing '?' on the service name (e.g.
         'cbt?', 'http?'). This LOOKS like a normal result and is easy to
         trust by mistake, but it means nmap never actually confirmed the
         protocol via a real probe/banner match — verified empirically:
         a custom TCP service returned 'cbt?', a real HTTP server returned
         plain 'http' with no '?'.
    Both get flagged, since a wrong-but-confident-looking guess is worse
    than an obviously-empty one — you're less likely to double-check it."""
    GENERIC_SERVICE_NAMES = {"", "unknown", "tcpwrapped"}
    for p in ctx.open_ports:
        service = (p.service or "").strip()
        service_lower = service.lower()
        version = (p.version or "").strip()

        if service_lower in GENERIC_SERVICE_NAMES or (not version and p.port not in GENERAL_TIPS):
            msg = (f"Port {p.port}/{p.protocol}: nmap's fingerprint is weak/generic "
                   f"({service or 'no service name'!r}, no version) — check it by hand, "
                   f"it could easily be an HTTP or custom service that this tool won't "
                   f"auto-enumerate: curl -v http://{ctx.target}:{p.port}/  or  "
                   f"nc -nv {ctx.target} {p.port}")
            if msg not in ctx.recommendations:
                ctx.recommendations.append(msg)

        if service.endswith("?"):
            msg = (f"Port {p.port}/{p.protocol}: nmap itself flagged this match as unconfirmed "
                   f"('{service}' — the trailing '?' means it's a port-based guess, not a "
                   f"verified probe match). Treat '{service.rstrip('?')}' as a hypothesis, not "
                   f"a fact — this is exactly the case where a Go binary or custom protocol "
                   f"gets silently misidentified. Verify manually: "
                   f"nc -nv {ctx.target} {p.port}  or  curl -v http://{ctx.target}:{p.port}/")
            if msg not in ctx.recommendations:
                ctx.recommendations.append(msg)
                ctx.quick_wins.append(f"Port {p.port}: unconfirmed nmap fingerprint ('{service}') "
                                       f"— verify by hand before trusting the auto-enumeration above.")


def print_quick_wins(ctx: ScanContext) -> None:
    section("QUICK WINS")
    if not ctx.flags_found and not ctx.quick_wins:
        out("  Nothing jumped out automatically yet — check the Next Steps "
            "checklist below and dig in manually.", "yellow")
        return

    if ctx.flags_found:
        out("  FLAGS FOUND:", "magenta", bold=True)
        if RICH_AVAILABLE:
            table = Table(box=box.SIMPLE_HEAVY)
            table.add_column("Flag")
            table.add_column("Source")
            for flag, source in ctx.flags_found:
                table.add_row(flag, source)
            console.print(table)
        else:
            for flag, source in ctx.flags_found:
                print(f"    {flag}   <-  {source}")
        print()

    flag_strings = {f for f, _ in ctx.flags_found}
    other_wins = [w for w in ctx.quick_wins if not any(f in w for f in flag_strings)]
    if other_wins:
        out("  Other promising leads:", "green", bold=True)
        for i, win in enumerate(dict.fromkeys(other_wins), 1):  # de-dupe, keep order
            out(f"    [{i}] {win}", "green")


def print_recommendations(ctx: ScanContext) -> None:
    section("Next Steps & Checklist")
    if not ctx.recommendations:
        out("  No specific recommendations — nothing actionable was detected.", "yellow")
        return

    if RICH_AVAILABLE:
        table = Table(box=box.SIMPLE_HEAVY, show_header=False)
        table.add_column("", justify="center", width=3)
        table.add_column("Recommendation")
        for i, rec in enumerate(ctx.recommendations, 1):
            table.add_row(f"[{i}]", rec)
        console.print(table)
    else:
        for i, rec in enumerate(ctx.recommendations, 1):
            print(f"  [{i}] {rec}")


def print_port_summary(ctx: ScanContext) -> None:
    section("Discovered Services Summary")
    if not ctx.open_ports:
        out("  No open ports recorded.", "yellow")
        return

    if RICH_AVAILABLE:
        table = Table(box=box.SIMPLE_HEAVY)
        table.add_column("Port")
        table.add_column("Proto")
        table.add_column("Service")
        table.add_column("Version / Banner")
        for p in sorted(ctx.open_ports, key=lambda x: (x.protocol, x.port)):
            table.add_row(str(p.port), p.protocol, p.service or "-", p.version or "-")
        console.print(table)
    else:
        for p in sorted(ctx.open_ports, key=lambda x: (x.protocol, x.port)):
            print(f"  {p.port:<6} {p.protocol:<5} {p.service:<15} {p.version}")


# ==========================================================================
# Final flag sweep — catches anything a spot-check missed
# ==========================================================================

def final_flag_sweep(ctx: ScanContext) -> None:
    """Analyze collected artifacts, including bounded archive/encoding support."""
    load_web_results(ctx)
    scanner = ArtifactScanner(ctx.flag_prefixes, ctx.include_hashes)
    merge_findings(ctx, scanner.scan([ctx.output_dir]))
    ctx.analysis_warnings.extend(scanner.warnings)


# ==========================================================================
# Setup helpers
# ==========================================================================

def make_output_dir(target: str, override: Optional[str]) -> Path:
    if override:
        out_dir = Path(override)
        out_dir.mkdir(parents=True, exist_ok=True)
        return out_dir
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r"[^\w.-]", "_", target)
    out_dir = Path.cwd() / f"ctf_results_{safe_target}_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def prompt_target() -> str:
    while True:
        if RICH_AVAILABLE:
            raw = console.input("[bold cyan]Enter target IP or hostname:[/bold cyan] ").strip()
        else:
            raw = input("Enter target IP or hostname: ").strip()

        if not raw:
            out("  Please enter a value.", "red")
            continue

        if is_valid_ip(raw):
            return raw

        if is_valid_hostname(raw):
            resolved = resolve_target(raw)
            if resolved:
                out(f"  Resolved {raw} -> {resolved}", "green")
                return raw  # nmap can take the hostname directly
            out(f"  Could not resolve hostname '{raw}'. Try again.", "red")
            continue

        out(f"  '{raw}' is not a valid IP address or hostname. Try again.", "red")


def validate_cli_target(raw: str) -> str:
    if is_valid_ip(raw):
        return raw
    if is_valid_hostname(raw) and resolve_target(raw):
        return raw
    out(f"'{raw}' is not a valid, resolvable IP address or hostname.", "red", bold=True)
    sys.exit(2)


def print_banner() -> None:
    if RICH_AVAILABLE:
        console.print(Panel.fit(
            Text(Brand.BANNER, style="bold green"),
            subtitle=f"v{Brand.VERSION} — by {Brand.AUTHOR} — {Brand.REPO}",
            border_style="green",
        ))
    else:
        print(Brand.BANNER)
        print(f"v{Brand.VERSION} — by {Brand.AUTHOR} — {Brand.REPO}\n")


def write_final_report(ctx: ScanContext) -> Path:
    report_path = ctx.output_dir / "SUMMARY.txt"
    lines = [
        "CTF Recon Assistant — Summary Report",
        f"Target: {ctx.target}",
        f"Generated: {datetime.now().isoformat()}",
        "",
        "=== FLAG CANDIDATES (unverified) ===" if ctx.flags_found else "=== FLAG CANDIDATES: none yet ===",
    ]
    for flag, src in ctx.flags_found:
        lines.append(f"  {flag}   <-  {src}")
    lines.append("")
    lines.append("=== Quick wins / promising leads ===")
    for w in dict.fromkeys(ctx.quick_wins):
        lines.append(f"  - {w}")
    lines.append("")
    lines.append("=== Open ports / services ===")
    for p in sorted(ctx.open_ports, key=lambda x: (x.protocol, x.port)):
        lines.append(f"  {p.port}/{p.protocol}  {p.service}  {p.version}")
    lines.append("")
    lines.append("=== Recommendations ===")
    for i, rec in enumerate(ctx.recommendations, 1):
        lines.append(f"  [{i}] {rec}")
    lines.extend(["", "=== Analysis warnings ===", *dict.fromkeys(ctx.analysis_warnings),
                  "", "All candidates, confidence and decoding provenance: REPORT.json"])
    report_path.write_text("\n".join(lines))
    write_triage(ctx)
    write_markdown_report(ctx)
    write_json_report(ctx, Brand.VERSION)
    return report_path


def write_markdown_report(ctx: ScanContext) -> Path:
    """Same content as SUMMARY.txt, formatted so it pastes cleanly into
    notes/write-ups (Obsidian, HackMD, a GitHub gist, etc.)."""
    md_path = ctx.output_dir / "SUMMARY.md"
    lines = [
        f"# CTF Recon Assistant — {ctx.target}",
        "",
        f"*Generated: {datetime.now().isoformat()}*",
        "",
        "## Flag candidates (unverified)",
        "",
    ]
    if ctx.flags_found:
        lines.append("| Flag | Source |")
        lines.append("|---|---|")
        for flag, src in ctx.flags_found:
            lines.append(f"| `{flag}` | {src} |")
    else:
        lines.append("_None yet._")
    lines.append("")
    lines.append("## Quick wins / promising leads")
    lines.append("")
    if ctx.quick_wins:
        for w in dict.fromkeys(ctx.quick_wins):
            lines.append(f"- {w}")
    else:
        lines.append("_Nothing automatic — see recommendations below._")
    lines.append("")
    lines.append("## Open ports / services")
    lines.append("")
    if ctx.open_ports:
        lines.append("| Port | Proto | Service | Version |")
        lines.append("|---|---|---|---|")
        for p in sorted(ctx.open_ports, key=lambda x: (x.protocol, x.port)):
            lines.append(f"| {p.port} | {p.protocol} | {p.service} | {p.version} |")
    else:
        lines.append("_None recorded._")
    lines.append("")
    lines.append("## Next steps")
    lines.append("")
    for i, rec in enumerate(ctx.recommendations, 1):
        lines.append(f"{i}. {rec}")
    def cell(value):
        return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "&#124;").replace("`", "&#96;").replace("\n", " ").replace("\r", " ")
    lines.extend(["", "## Candidate evidence", "", "All matches are unverified. Line numbers refer to the decoded text when a transformation was applied.", "",
                  "| Candidate | Confidence | Source | Transformation | Line |",
                  "|---|---|---|---|---|"])
    for finding in sorted(ctx.flag_evidence, key=lambda f: {"high": 0, "medium": 1, "low": 2}[f["confidence"]]):
        lines.append("| " + " | ".join(cell(finding[k]) for k in ("value", "confidence", "source", "transform", "line")) + " |")
    if ctx.analysis_warnings:
        lines.extend(["", "## Analysis warnings", ""] + ["- " + cell(w) for w in dict.fromkeys(ctx.analysis_warnings)])
    md_path.write_text("\n".join(lines))
    return md_path


# ==========================================================================
# CLI
# ==========================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ctf_assistant.py",
        description="Modular CTF reconnaissance & flag-hunting assistant.",
    )
    p.add_argument("-t", "--target", help="Target IP or hostname (skips the interactive prompt).")
    p.add_argument("-p", "--ports", help="Comma-separated ports to use directly, skipping "
                                          "Phase 1's full port sweep (e.g. -p 80,22,445). "
                                          "Use this once you already know the open ports and "
                                          "want to save time in a timed competition.")
    p.add_argument("--fast", action="store_true",
                    help="Phase 1 scans only the top 1000 ports instead of all 65535 — much "
                         "faster, at the risk of missing a service on an unusual port.")
    p.add_argument("--min-rate", type=int, default=1000,
                    help="Nmap --min-rate for Phase 1 (default: 1000). Lower this (e.g. 300) "
                         "on lossy CTF VPNs (HTB/THM) if you're seeing inconsistent results or "
                         "ports that come and go between runs.")
    p.add_argument("--udp", action="store_true",
                    help="Also run a quick UDP port sweep (needs root/sudo for accurate results).")
    p.add_argument("--udp-top-ports", type=int, default=50,
                    help="How many top UDP ports to check with --udp (default: 50).")
    p.add_argument("--thorough", action="store_true",
                    help="Use a bigger wordlist and be more exhaustive in HTTP enumeration.")
    p.add_argument("--wordlist", help="Exact wordlist path to use for gobuster/ffuf, overriding "
                                       "auto-detection. Point this at raft-medium-directories.txt "
                                       "or any custom list without editing the script.")
    p.add_argument("--dirb-timeout", type=int, default=300,
                    help="Timeout in seconds for gobuster/ffuf per port (default: 300).")
    p.add_argument("--nikto-timeout", type=int, default=150,
                    help="Timeout in seconds for nikto per port (default: 150 — nikto can be slow; "
                         "raise it if you have time to spare, lower it to protect the clock).")
    p.add_argument("--vhost", action="store_true",
                    help="Also brute-force virtual hosts via the Host header — common on CTF "
                         "web boxes that route by vhost (e.g. HTB machines ending in .htb).")
    p.add_argument("--vhost-domain", help="Base domain to append during --vhost fuzzing "
                                           "(e.g. 'target.htb'). Defaults to the target itself "
                                           "if it's a hostname; required if the target is a bare IP.")
    p.add_argument("--vhost-wordlist", help="Wordlist for --vhost fuzzing. Defaults to a small "
                                             "built-in list of common subdomain names if omitted.")
    p.add_argument("--no-http", action="store_true", help="Skip HTTP/HTTPS enumeration in Phase 3.")
    p.add_argument("--no-smb", action="store_true", help="Skip SMB enumeration in Phase 3.")
    p.add_argument("--no-ftp", action="store_true", help="Skip FTP enumeration in Phase 3.")
    p.add_argument("--no-windows", action="store_true",
                    help="Skip the Windows/AD enumeration phase (auto-triggered by any "
                         "Kerberos/RPC/SMB/LDAP/RDP/WinRM port — Phase 3b).")
    p.add_argument("--windows-timeout", type=int, default=180,
                    help="Timeout in seconds for each Windows/AD enumeration sub-step "
                         "(SMB scripts, enum4linux-ng, etc.) (default: 180).")
    p.add_argument("-o", "--output-dir", help="Use this exact output directory instead of "
                                               "auto-generating a timestamped one.")
    p.add_argument("--resume", metavar="DIR",
                    help="Resume into an existing output directory: phases whose log files "
                         "already exist and look complete are skipped instead of re-run. "
                         "Use this after a Ctrl+C instead of starting over from scratch.")
    p.add_argument("--analyze", nargs="+", metavar="PATH", help="Offline analysis of files/directories/ZIP/GZIP; no network access.")
    p.add_argument("--import-nmap", metavar="XML", help="Offline import of an Nmap -oX file; combine with --analyze.")
    p.add_argument("--flag-prefix", action="append", default=[], help="Recognize an additional event prefix; repeatable (e.g. --flag-prefix MYCTF).")
    p.add_argument("--include-hashes", action="store_true", help="Include unlabelled 32-hex strings as low-confidence evidence in REPORT.json.")
    p.add_argument("--version", action="version", version=Brand.VERSION)
    p.add_argument("--web-url", metavar="URL", help="Run just the bounded web mapper against an assigned HTTP(S) URL; no Nmap needed.")
    p.add_argument("--no-crawl", action="store_true", help="Use legacy HTTP discovery without the new web mapper.")
    p.add_argument("--web-pages", type=int, default=60, help="Web mapper request cap per origin, including probes/redirects (default: 60).")
    p.add_argument("--web-depth", type=int, default=3, help="Web mapper link depth (default: 3; maximum: 8).")
    p.add_argument("--web-seconds", type=int, default=120, help="Cumulative mapper time budget per origin (default: 120; excludes other tools).")
    p.add_argument("--web-delay", type=float, default=0.1, help="Minimum interval between web mapper requests in seconds (default: 0.1).")
    return p


# ==========================================================================
# Main orchestration
# ==========================================================================

def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()
    for name in ("min_rate", "udp_top_ports", "dirb_timeout", "nikto_timeout", "windows_timeout"):
        if getattr(args, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    if args.udp_top_ports > 65535:
        parser.error("--udp-top-ports must be <= 65535")
    if any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,31}", prefix) for prefix in args.flag_prefix):
        parser.error("Flag prefixes must be 1–32 letters/digits/underscores, beginning with a letter")
    if args.ports:
        try:
            parsed_ports = list(dict.fromkeys(int(x.strip()) for x in args.ports.split(",")))
            if not parsed_ports or any(not 1 <= port <= 65535 for port in parsed_ports):
                raise ValueError
        except ValueError:
            parser.error("--ports requires comma-separated integers in 1..65535")
    if not 4 <= args.web_pages <= 1000:
        parser.error("--web-pages must be between 4 and 1000")
    if not 0 <= args.web_depth <= 8 or not 1 <= args.web_seconds <= 3600:
        parser.error("--web-depth must be 0..8 and --web-seconds must be 1..3600")
    if not 0 <= args.web_delay <= 10:
        parser.error("--web-delay must be between 0 and 10 seconds")
    if args.web_url:
        if args.target or args.analyze or args.import_nmap or args.resume or args.no_crawl or args.no_http:
            parser.error("--web-url cannot be combined with --target, offline inputs, --resume, --no-crawl or --no-http")
        try:
            url = canonical_url(args.web_url)
            output_dir = make_output_dir("web", args.output_dir)
            if any(output_dir.iterdir()):
                parser.error("--web-url needs a new/empty output directory to keep challenge evidence separate")
            ctx = ScanContext(target=url, output_dir=output_dir, flag_prefixes=args.flag_prefix,
                              include_hashes=args.include_hashes, web_pages=args.web_pages,
                              web_depth=args.web_depth, web_seconds=args.web_seconds, web_delay=args.web_delay)
            mapper = new_web_mapper(ctx, url)
            interrupted = False
            try:
                mapper.run()
            except KeyboardInterrupt:
                interrupted = True
            add_web_result(ctx, vars(mapper.result))
            final_flag_sweep(ctx)
            write_final_report(ctx)
            out(f"Web map: {len(mapper.result.pages)} pages, {len(mapper.result.leads)} leads; {len(ctx.flags_found)} candidate observations.", "green")
            out(f"Read {output_dir.resolve() / 'NEXT_STEPS.md'} and WEB_MAP.md")
            return 130 if interrupted else (0 if mapper.result.pages else 1)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
    if args.analyze or args.import_nmap:
        if args.resume:
            parser.error("Offline analysis does not use --resume; pass the directory to --analyze")
        try:
            imported = parse_nmap(args.import_nmap, args.target) if args.import_nmap else None
            output_dir = make_output_dir("offline", args.output_dir)
            ctx = ScanContext(target=imported['target'] if imported else (args.target or "offline"),
                              output_dir=output_dir, flag_prefixes=args.flag_prefix,
                              include_hashes=args.include_hashes)
            if imported:
                ctx.open_ports = [OpenPort(**port) for port in imported['ports']]
                for script in imported['scripts']:
                    record_flags(ctx, script['output'], f"{args.import_nmap}: NSE {script['id']}")
                build_recommendations(ctx)
            if args.analyze:
                missing = [str(path) for path in args.analyze if not Path(path).exists()]
                if missing:
                    parser.error("Missing analysis input: " + ", ".join(missing))
                scanner = ArtifactScanner(args.flag_prefix, args.include_hashes)
                merge_findings(ctx, scanner.scan(args.analyze))
                ctx.analysis_warnings.extend(scanner.warnings)
            write_final_report(ctx)
            out(f"Offline analysis: {len({f['value'] for f in ctx.flag_evidence})} unique candidates; {len(ctx.analysis_warnings)} warning(s).", "green")
            out(f"Reports: {output_dir.resolve()} (SUMMARY.txt, SUMMARY.md, REPORT.json)")
            return 0
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        except Exception as exc:
            out(f"Offline analysis failed: {exc}", "red")
            return 2

    print_banner()
    out("Only scan systems you own or are explicitly authorized to test.\n", "yellow", bold=True)

    try:
        if args.target:
            raw_target = validate_cli_target(args.target)
        else:
            raw_target = prompt_target()
    except KeyboardInterrupt:
        out("\nAborted before target entry.", "red")
        return 130
    except EOFError:
        out("\nNo input received (EOF). Aborting.", "red")
        return 1

    resume_mode = bool(args.resume)
    if resume_mode:
        output_dir = Path(args.resume)
        if not output_dir.exists():
            out(f"--resume directory does not exist: {output_dir}", "red", bold=True)
            return 2
        out(f"Resuming into existing output directory: {output_dir}\n", "blue", bold=True)
    else:
        output_dir = make_output_dir(raw_target, args.output_dir)

    # Bind phase markers to the target and scan settings so resume cannot mix evidence.
    manifest = output_dir / "session.json"
    settings = {k: v for k, v in vars(args).items() if k not in {"resume", "output_dir", "target"}}
    session = {"target": raw_target, "settings": settings, "tool_version": Brand.VERSION}
    if manifest.exists():
        try:
            if json.loads(manifest.read_text()) != session:
                out("Target/options/version differ from this directory's session; use a new output directory.", "red")
                return 2
        except (ValueError, OSError):
            out("Cannot read session metadata; use a new output directory.", "red")
            return 2
    elif any(output_dir.iterdir()):
        out("Existing results have no session metadata. Use a new directory, or --analyze for offline review.", "red")
        return 2
    manifest.write_text(json.dumps(session, indent=2))
    ctx = ScanContext(target=raw_target, output_dir=output_dir, flag_prefixes=args.flag_prefix,
                      include_hashes=args.include_hashes)
    ctx.crawl_enabled = not args.no_crawl
    ctx.web_pages, ctx.web_depth = args.web_pages, args.web_depth
    ctx.web_seconds, ctx.web_delay = args.web_seconds, args.web_delay
    out(f"Output directory: {output_dir}\n", "blue")

    ctx.tool_status = check_tools()
    print_tool_checklist(ctx.tool_status)

    try:
        if args.ports:
            try:
                ports = parsed_ports
            except ValueError:
                out(f"Invalid --ports value: {args.ports!r}. Use e.g. -p 80,22,445", "red", bold=True)
                return 2
            out(f"Using user-supplied ports {ports} — skipping Phase 1 full sweep.\n", "blue")
        elif resume_mode and (resumed := resume_load_quick_scan(ctx)) is not None:
            ports = resumed
        else:
            ports = phase_quick_scan(ctx, fast=args.fast, min_rate=args.min_rate)

        for pnum in ports:
            if not any(p.port == pnum and p.protocol == "tcp" for p in ctx.open_ports):
                ctx.open_ports.append(OpenPort(pnum))

        if not (resume_mode and resume_load_deep_scan(ctx)):
            phase_deep_scan(ctx, ports)

        if args.udp:
            udp_marker = ctx.output_dir / "nmap" / "udp_scan.done"
            if resume_mode and phase_is_done(udp_marker) and (ctx.output_dir / "nmap" / "udp_scan.txt").exists():
                udp_output = (ctx.output_dir / "nmap" / "udp_scan.txt").read_text(errors="replace")
                for match in re.finditer(r"(?m)^\s*(\d+)/udp\s+(open(?:\|filtered)?)\s+(\S+)", udp_output):
                    number = int(match.group(1))
                    if not any(p.port == number and p.protocol == "udp" for p in ctx.open_ports):
                        ctx.open_ports.append(OpenPort(number, "udp", match.group(3), state=match.group(2)))
                record_flags(ctx, udp_output, "nmap UDP output")
                out("  [resume] Restored UDP scan evidence.", "blue")
            else:
                phase_udp_scan(ctx, top_ports=args.udp_top_ports)

        print_port_summary(ctx)

        flag_low_confidence_fingerprints(ctx)

        # searchsploit pass — once we have real version strings from -sC -sV
        for p in ctx.open_ports:
            searchsploit_lookup(ctx, p, ctx.tool_status)

        if args.no_http or args.no_smb or args.no_ftp:
            skipped = []
            if args.no_http:
                skipped.append("HTTP")
            if args.no_smb:
                skipped.append("SMB")
            if args.no_ftp:
                skipped.append("FTP")
            out(f"Skipping phases: {', '.join(skipped)} (per CLI flags)\n", "blue")

        # Temporarily filter which ports phase_service_enum considers, based
        # on --no-http/--no-smb/--no-ftp, without touching the real list.
        original_ports = ctx.open_ports
        filtered = []
        for p in original_ports:
            if p.protocol != "tcp" or p.state != "open":
                continue
            if args.no_http and _matches(p, HTTP_PORTS, HTTP_SERVICE_NAMES):
                continue
            if args.no_smb and _matches(p, SMB_PORTS, SMB_SERVICE_NAMES):
                continue
            if args.no_ftp and _matches(p, FTP_PORTS, FTP_SERVICE_NAMES):
                continue
            filtered.append(p)
        ctx.open_ports = filtered
        try:
            phase_service_enum(ctx, ctx.tool_status, args.thorough, args.wordlist, args.dirb_timeout,
                                args.nikto_timeout, args.vhost, args.vhost_domain, args.vhost_wordlist,
                                resume=resume_mode, no_windows=args.no_windows,
                                windows_timeout=args.windows_timeout)
        finally:
            ctx.open_ports = original_ports

        build_recommendations(ctx)
        final_flag_sweep(ctx)

        print_quick_wins(ctx)
        print_recommendations(ctx)

        report_path = write_final_report(ctx)
        section("Done")
        out(f"Full logs saved under: {ctx.output_dir}", "green")
        out(f"Summary report: {report_path} (and SUMMARY.md)", "green", bold=True)
        out(f"Prioritized checklist: {ctx.output_dir / 'NEXT_STEPS.md'}; web map: WEB_MAP.md", "green")
        if ctx.flags_found:
            out(f"\n*** {len(ctx.flags_found)} possible flag(s) found — check QUICK WINS above! ***",
                "magenta", bold=True)
        return 0

    except KeyboardInterrupt:
        out("\n\n[!] Scan interrupted by user (Ctrl+C).", "red", bold=True)
        out("Partial results (if any) have been saved to:", "yellow")
        out(f"  {ctx.output_dir}", "yellow")
        out(f"  Resume later with: --resume {ctx.output_dir} -t {ctx.target}", "yellow")
        build_recommendations(ctx)
        final_flag_sweep(ctx)
        if ctx.open_ports:
            print_port_summary(ctx)
        print_quick_wins(ctx)
        if ctx.recommendations:
            print_recommendations(ctx)
        write_final_report(ctx)
        return 130
    except Exception as e:  # noqa: BLE001 - top-level safety net for a CLI tool
        out(f"\n[!] Unexpected error: {e}", "red", bold=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
