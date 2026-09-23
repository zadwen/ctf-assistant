#!/usr/bin/env python3
"""
ctf_assistant.py — Modular interactive CTF Reconnaissance & Assistant tool.

Author:  zadwen
License: MIT

Automates the standard early-recon workflow used in CTF / lab environments
(HackTheBox, TryHackMe, OSCP-style labs, your own test VMs):

    1. Target validation
    2. Tool-availability checklist
    3. Fast port sweep (Nmap)
    4. Deep -sC -sV scan on discovered ports only
    5. Service-specific enumeration (HTTP dir-busting, SMB anon shares,
       FTP anon login)
    6. A generated "Next Steps" checklist based on what was actually found

IMPORTANT: Only run this against systems you own or are explicitly
authorized to test (CTF boxes, your own lab VMs, engagements you're
scoped for). Unauthorized scanning of systems you don't control is
illegal in most jurisdictions.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
import sys
import time
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

    console = Console()
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    console = None


# ==========================================================================
# core/branding.py equivalent — kept inline here for a single-file deliverable
# ==========================================================================

class Brand:
    NAME = "CTF Recon Assistant"
    AUTHOR = "zadwen"
    VERSION = "1.0.0"
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
        console.rule(f"[bold cyan]{title}[/bold cyan]")
    else:
        print(f"\n{Ansi.BOLD}{Ansi.CYAN}=== {title} ==={Ansi.RESET}")


# ==========================================================================
# Data model
# ==========================================================================

@dataclass
class OpenPort:
    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""


@dataclass
class ScanContext:
    target: str
    output_dir: Path
    open_ports: list[OpenPort] = field(default_factory=list)
    tool_status: dict[str, bool] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)


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

REQUIRED_TOOLS = {
    "nmap": "Port scanning & service/version detection",
    "gobuster": "Directory/file brute-forcing (preferred)",
    "ffuf": "Directory/file brute-forcing (fallback if gobuster missing)",
    "nikto": "Web server vulnerability scanning",
    "smbclient": "SMB anonymous share enumeration",
    "ftp": "FTP anonymous login check",
}


def check_tools() -> dict[str, bool]:
    return {tool: shutil.which(tool) is not None for tool in REQUIRED_TOOLS}


def print_tool_checklist(status: dict[str, bool]) -> None:
    section("Prerequisite Tool Check")
    if RICH_AVAILABLE:
        table = Table(box=box.SIMPLE_HEAVY)
        table.add_column("Tool")
        table.add_column("Purpose")
        table.add_column("Status", justify="center")
        for tool, purpose in REQUIRED_TOOLS.items():
            ok = status.get(tool, False)
            mark = "[bold green]READY[/bold green]" if ok else "[bold red]MISSING[/bold red]"
            table.add_row(tool, purpose, mark)
        console.print(table)
    else:
        for tool, purpose in REQUIRED_TOOLS.items():
            ok = status.get(tool, False)
            mark = f"{Ansi.GREEN}READY{Ansi.RESET}" if ok else f"{Ansi.RED}MISSING{Ansi.RESET}"
            print(f"  {tool:<12} {purpose:<45} [{mark}]")

    missing = [t for t, ok in status.items() if not ok]
    # gobuster/ffuf are interchangeable — don't hard-fail on one of the pair
    hard_missing = [t for t in missing if not (t in ("gobuster", "ffuf") and status.get(
        "ffuf" if t == "gobuster" else "gobuster"))]
    if hard_missing:
        out(f"\n  Missing tools: {', '.join(hard_missing)}. Install with e.g.:", "yellow")
        out(f"    sudo apt install {' '.join(t for t in hard_missing if t != 'ffuf')}", "yellow")
        if "ffuf" in hard_missing:
            out("    sudo apt install ffuf   # or: go install github.com/ffuf/ffuf/v2@latest", "yellow")
        out("  Affected phases will be skipped automatically.\n", "yellow")
    else:
        out("\n  All tools available.\n", "green")


# ==========================================================================
# Command runner
# ==========================================================================

def run_command(cmd: list[str], log_path: Path, timeout: Optional[int] = None) -> tuple[int, str]:
    """
    Run a command, streaming nothing to the terminal but capturing full
    output to log_path. Returns (returncode, combined_output).
    Raises KeyboardInterrupt upward untouched so the caller can handle Ctrl+C.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        output = proc.stdout or ""
        log_path.write_text(output)
        return proc.returncode, output
    except FileNotFoundError:
        msg = f"[ERROR] Command not found: {cmd[0]}"
        log_path.write_text(msg)
        return 127, msg
    except subprocess.TimeoutExpired as e:
        partial = (e.stdout or "") if isinstance(e.stdout, str) else ""
        msg = partial + f"\n[ERROR] Command timed out after {timeout}s: {' '.join(cmd)}"
        log_path.write_text(msg)
        return 124, msg


def spinner_run(description: str, cmd: list[str], log_path: Path, timeout: Optional[int] = None) -> tuple[int, str]:
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
            result = run_command(cmd, log_path, timeout=timeout)
            progress.update(task, completed=1)
        return result
    else:
        print(f"  -> {description} ...", end="", flush=True)
        result = run_command(cmd, log_path, timeout=timeout)
        print(" done.")
        return result


# ==========================================================================
# Phase 1: Quick Nmap scan
# ==========================================================================

def phase_quick_scan(ctx: ScanContext) -> list[int]:
    section("Phase 1 — Quick Port Sweep (Nmap)")
    log_path = ctx.output_dir / "nmap" / "quick_scan.txt"

    cmd = [
        "nmap",
        "-T4",
        "--min-rate", "1000",
        "-p-",              # all 65535 ports
        "-Pn",              # skip host discovery — CTF boxes often block ICMP
        "--open",
        "-oN", str(log_path.with_suffix(".nmap")),
        ctx.target,
    ]
    out(f"  Running: {' '.join(cmd)}", "bright_black")
    rc, output = spinner_run("Scanning all 65535 ports...", cmd, log_path)

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

    return ports


# ==========================================================================
# Phase 2: Deep scan on discovered ports only
# ==========================================================================

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
        ctx.target,
    ]
    out(f"  Running: {' '.join(cmd)}", "bright_black")
    rc, output = spinner_run(f"Running -sC -sV against {port_list}...", cmd, log_path)

    if rc == 127:
        out("  nmap not installed — skipping.", "red")
        return

    # Parse "PORT STATE SERVICE VERSION" lines for richer service/version info
    for line in output.splitlines():
        m = re.match(
            r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$", line.strip()
        )
        if m:
            port_num = int(m.group(1))
            proto = m.group(2)
            service = m.group(3)
            version = m.group(4).strip()
            existing = next((p for p in ctx.open_ports if p.port == port_num), None)
            if existing:
                existing.service = service
                existing.version = version
            else:
                ctx.open_ports.append(OpenPort(port_num, proto, service, version))

    out(f"  Deep scan complete. Log: {log_path.with_suffix('.nmap')}", "green")


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


def _matches(port: "OpenPort", port_set: set[int], service_names: set[str]) -> bool:
    if port.port in port_set:
        return True
    service = port.service.lower()
    return any(name in service for name in service_names)


# Candidate wordlist locations, in preference order. The Kali convention
# (/usr/share/wordlists/dirb/common.txt) is checked first since it's the
# most commonly referenced path; the plain `dirb` package on Ubuntu/Zorin
# installs to /usr/share/dirb/wordlists/common.txt instead.
WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]


def find_wordlist() -> Optional[str]:
    for candidate in WORDLIST_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return None


def phase_http_enum(ctx: ScanContext, port: OpenPort, tool_status: dict[str, bool]) -> None:
    scheme = "https" if port.port in (443, 8443) else "http"
    base_url = f"{scheme}://{ctx.target}:{port.port}/"
    out(f"\n  [HTTP] Enumerating {base_url}", "cyan", bold=True)

    wordlist = find_wordlist()
    if not wordlist:
        out("    No dir-busting wordlist found. Checked:", "yellow")
        for c in WORDLIST_CANDIDATES:
            out(f"      {c}", "yellow")
        out("    Install with: sudo apt install dirb   (or install seclists)", "yellow")
    elif tool_status.get("gobuster"):
        log_path = ctx.output_dir / "http" / f"gobuster_{port.port}.txt"
        cmd = [
            "gobuster", "dir",
            "-u", base_url,
            "-w", wordlist,
            "-q",
            "-k",  # skip TLS verification, common on CTF self-signed certs
        ]
        spinner_run(f"gobuster dir-busting port {port.port}...", cmd, log_path, timeout=300)
        out(f"    gobuster log: {log_path}", "green")
    elif tool_status.get("ffuf"):
        log_path = ctx.output_dir / "http" / f"ffuf_{port.port}.txt"
        cmd = [
            "ffuf",
            "-u", f"{base_url}FUZZ",
            "-w", wordlist,
            "-of", "csv",
            "-o", str(log_path.with_suffix(".csv")),
            "-s",
        ]
        spinner_run(f"ffuf dir-busting port {port.port}...", cmd, log_path, timeout=300)
        out(f"    ffuf log: {log_path.with_suffix('.csv')}", "green")
    else:
        out("    Neither gobuster nor ffuf available — skipping dir-busting.", "yellow")

    if tool_status.get("nikto"):
        log_path = ctx.output_dir / "http" / f"nikto_{port.port}.txt"
        cmd = ["nikto", "-h", f"{ctx.target}:{port.port}", "-nointeractive"]
        spinner_run(f"nikto scanning port {port.port}...", cmd, log_path, timeout=300)
        out(f"    nikto log: {log_path}", "green")
    else:
        out("    nikto not available — skipping web vuln scan.", "yellow")

    ctx.recommendations.append(
        f"HTTP port {port.port} open -> manually check {base_url}robots.txt, "
        f"view page source, check for /admin, /login, comments in HTML."
    )


def phase_smb_enum(ctx: ScanContext, port: OpenPort, tool_status: dict[str, bool]) -> None:
    out(f"\n  [SMB] Checking anonymous access on port {port.port}", "cyan", bold=True)
    if not tool_status.get("smbclient"):
        out("    smbclient not available — skipping.", "yellow")
        ctx.recommendations.append(
            f"SMB port {port.port} open -> install smbclient and test anonymous "
            f"login manually: smbclient -L //{ctx.target}/ -N"
        )
        return

    log_path = ctx.output_dir / "smb" / "anon_list_shares.txt"
    cmd = ["smbclient", "-L", f"//{ctx.target}/", "-N"]  # -N = no password
    rc, output = spinner_run("Listing SMB shares anonymously...", cmd, log_path, timeout=60)

    if "NT_STATUS_ACCESS_DENIED" in output or "NT_STATUS_LOGON_FAILURE" in output:
        out("    Anonymous access denied.", "yellow")
    elif rc == 0 and "Sharename" in output:
        out("    Anonymous SMB listing succeeded! See log for share names.", "green", bold=True)
        ctx.recommendations.append(
            f"SMB port {port.port} -> anonymous listing SUCCEEDED "
            f"({log_path}). Try: smbclient //{ctx.target}/<share> -N"
        )
    else:
        out("    Inconclusive — check log manually.", "yellow")

    ctx.recommendations.append(
        f"SMB port {port.port} open -> also try enum4linux-ng and check for "
        f"null session / guest access, and smbmap."
    )


def phase_ftp_enum(ctx: ScanContext, port: OpenPort, tool_status: dict[str, bool]) -> None:
    out(f"\n  [FTP] Checking anonymous login on port {port.port}", "cyan", bold=True)
    if not tool_status.get("ftp"):
        out("    ftp client not available — skipping.", "yellow")
        ctx.recommendations.append(
            f"FTP port {port.port} open -> install ftp client and test manually: "
            f"ftp {ctx.target}"
        )
        return

    log_path = ctx.output_dir / "ftp" / "anon_login.txt"
    # Feed credentials via stdin to the ftp client non-interactively
    script = f"open {ctx.target} {port.port}\nuser anonymous anonymous@ctf.local\nls\nbye\n"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            ["ftp", "-n", "-v"],  # -n: no auto-login (we drive it via script); -v: echo server responses
            input=script,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )
        output = proc.stdout or ""
        log_path.write_text(output)
    except FileNotFoundError:
        output = "[ERROR] ftp binary not found."
        log_path.write_text(output)
    except subprocess.TimeoutExpired:
        output = "[ERROR] ftp connection timed out."
        log_path.write_text(output)

    if "230" in output:  # 230 = successful login
        out("    Anonymous FTP login SUCCEEDED!", "green", bold=True)
        ctx.recommendations.append(
            f"FTP port {port.port} -> anonymous login SUCCEEDED ({log_path}). "
            f"Browse and download files: ftp {ctx.target}"
        )
    elif "530" in output:  # 530 = login incorrect
        out("    Anonymous login rejected.", "yellow")
        ctx.recommendations.append(
            f"FTP port {port.port} open -> anonymous login rejected; try known/weak creds."
        )
    else:
        out("    Inconclusive — check log manually.", "yellow")
        ctx.recommendations.append(f"FTP port {port.port} open -> verify manually: ftp {ctx.target}")


def phase_service_enum(ctx: ScanContext, tool_status: dict[str, bool]) -> None:
    section("Phase 3 — Service-Specific Enumeration")
    if not ctx.open_ports:
        out("  Skipped — no open ports to enumerate.", "yellow")
        return

    matched_any = False
    for p in ctx.open_ports:
        if _matches(p, HTTP_PORTS, HTTP_SERVICE_NAMES):
            phase_http_enum(ctx, p, tool_status)
            matched_any = True
        if _matches(p, SMB_PORTS, SMB_SERVICE_NAMES):
            phase_smb_enum(ctx, p, tool_status)
            matched_any = True
        if _matches(p, FTP_PORTS, FTP_SERVICE_NAMES):
            phase_ftp_enum(ctx, p, tool_status)
            matched_any = True

    if not matched_any:
        out("  No HTTP/SMB/FTP ports among open ports — nothing to auto-enumerate here.", "yellow")


# ==========================================================================
# Recommendation engine (general, port-driven)
# ==========================================================================

GENERAL_TIPS = {
    21: "FTP (21) open -> test anonymous login; check for writable dirs; banner-grab version for known CVEs.",
    22: "SSH (22) open -> banner-grab version; check for weak/reused creds; rarely the initial foothold in CTF.",
    23: "Telnet (23) open -> often misconfigured/legacy; try default creds.",
    25: "SMTP (25) open -> try VRFY/EXPN user enumeration; check for open relay.",
    53: "DNS (53) open -> try zone transfer: dig axfr @<target> <domain>.",
    80: "HTTP (80) open -> inspect page source, check /robots.txt, /sitemap.xml, HTTP headers.",
    110: "POP3 (110) open -> banner-grab; check for cleartext creds if paired with another service.",
    111: "RPCbind (111) open -> run rpcinfo -p <target>; often pairs with NFS.",
    139: "SMB (139) open -> test anonymous/null sessions; try enum4linux-ng.",
    143: "IMAP (143) open -> banner-grab; check auth mechanisms.",
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
        for p in sorted(ctx.open_ports, key=lambda x: x.port):
            table.add_row(str(p.port), p.protocol, p.service or "-", p.version or "-")
        console.print(table)
    else:
        for p in sorted(ctx.open_ports, key=lambda x: x.port):
            print(f"  {p.port:<6} {p.protocol:<5} {p.service:<15} {p.version}")


# ==========================================================================
# Setup helpers
# ==========================================================================

def make_output_dir(target: str) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r"[^\w.-]", "_", target)
    out_dir = Path.cwd() / f"ctf_results_{safe_target}_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def prompt_target() -> tuple[str, str]:
    """Returns (original_input, resolved_ip_or_hostname_to_scan)."""
    while True:
        if RICH_AVAILABLE:
            raw = console.input("[bold cyan]Enter target IP or hostname:[/bold cyan] ").strip()
        else:
            raw = input("Enter target IP or hostname: ").strip()

        if not raw:
            out("  Please enter a value.", "red")
            continue

        if is_valid_ip(raw):
            return raw, raw

        if is_valid_hostname(raw):
            resolved = resolve_target(raw)
            if resolved:
                out(f"  Resolved {raw} -> {resolved}", "green")
                # Nmap can take the hostname directly; keep it for readability
                return raw, raw
            out(f"  Could not resolve hostname '{raw}'. Try again.", "red")
            continue

        out(f"  '{raw}' is not a valid IP address or hostname. Try again.", "red")


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
        f"CTF Recon Assistant — Summary Report",
        f"Target: {ctx.target}",
        f"Generated: {datetime.now().isoformat()}",
        "",
        "Open ports / services:",
    ]
    for p in sorted(ctx.open_ports, key=lambda x: x.port):
        lines.append(f"  {p.port}/{p.protocol}  {p.service}  {p.version}")
    lines.append("")
    lines.append("Recommendations:")
    for i, rec in enumerate(ctx.recommendations, 1):
        lines.append(f"  [{i}] {rec}")
    report_path.write_text("\n".join(lines))
    return report_path


# ==========================================================================
# Main orchestration
# ==========================================================================

def main() -> int:
    print_banner()
    out("Only scan systems you own or are explicitly authorized to test.\n", "yellow", bold=True)

    try:
        raw_target, scan_target = prompt_target()
    except KeyboardInterrupt:
        out("\nAborted before target entry.", "red")
        return 130
    except EOFError:
        out("\nNo input received (EOF). Aborting.", "red")
        return 1

    output_dir = make_output_dir(raw_target)
    ctx = ScanContext(target=scan_target, output_dir=output_dir)
    out(f"Output directory: {output_dir}\n", "blue")

    ctx.tool_status = check_tools()
    print_tool_checklist(ctx.tool_status)

    try:
        ports = phase_quick_scan(ctx)
        # seed ctx.open_ports before deep scan enriches them
        for pnum in ports:
            if not any(p.port == pnum for p in ctx.open_ports):
                ctx.open_ports.append(OpenPort(pnum))

        phase_deep_scan(ctx, ports)
        print_port_summary(ctx)

        phase_service_enum(ctx, ctx.tool_status)

        build_recommendations(ctx)
        print_recommendations(ctx)

        report_path = write_final_report(ctx)
        section("Done")
        out(f"Full logs saved under: {ctx.output_dir}", "green")
        out(f"Summary report: {report_path}", "green", bold=True)
        return 0

    except KeyboardInterrupt:
        out("\n\n[!] Scan interrupted by user (Ctrl+C).", "red", bold=True)
        out("Partial results (if any) have been saved to:", "yellow")
        out(f"  {ctx.output_dir}", "yellow")
        if ctx.open_ports:
            print_port_summary(ctx)
        if ctx.recommendations:
            build_recommendations(ctx)
            print_recommendations(ctx)
        write_final_report(ctx)
        return 130
    except Exception as e:  # noqa: BLE001 - top-level safety net for a CLI tool
        out(f"\n[!] Unexpected error: {e}", "red", bold=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
