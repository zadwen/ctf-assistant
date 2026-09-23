# CTF Recon Assistant

A modular, interactive CLI reconnaissance tool for CTF boxes and lab VMs on
Linux (tested on Ubuntu/Zorin OS). Automates the Nmap sweep → deep scan →
service-specific enumeration → "what to try next" workflow.

**Only run this against systems you own or are explicitly authorized to
test** (CTF platforms, your own lab VMs, scoped engagements). Unauthorized
scanning is illegal in most jurisdictions.

## What it does

1. **Target input & validation** — prompts for an IP or hostname, validates
   it, resolves hostnames, and creates a timestamped output directory
   (`./ctf_results_<target>_<timestamp>/`).
2. **Tool checklist** — checks for `nmap`, `gobuster`/`ffuf`, `nikto`,
   `smbclient`, `ftp` and shows a READY/MISSING table. Missing tools cause
   their specific phase to be skipped, not a crash.
3. **Phase 1 — Quick scan**: `nmap -T4 --min-rate 1000 -p- -Pn --open`
   across all 65535 ports to find what's open, fast.
4. **Phase 2 — Deep scan**: `nmap -sC -sV -Pn -p <discovered ports>` —
   version detection and default scripts, run only against ports that are
   actually open (not a blind full re-scan).
5. **Phase 3 — Service-specific enumeration**, triggered by port number
   *or* by the service name Nmap detected (so a service on a non-standard
   port, e.g. FTP on 2121, still gets caught):
   - **HTTP/HTTPS** → `gobuster dir` (falls back to `ffuf` if `gobuster`
     isn't installed) using `/usr/share/wordlists/dirb/common.txt` if
     present, with automatic fallback to the Ubuntu/Zorin `dirb` package
     path (`/usr/share/dirb/wordlists/common.txt`) or SecLists if either
     is installed instead. Also runs `nikto` if available.
   - **SMB** → `smbclient -L //<target>/ -N` to test anonymous share
     listing.
   - **FTP** → scripted anonymous login attempt (`user anonymous ...`),
     parsed against the real FTP response codes (`230` success / `530`
     rejected).
6. **Next Steps & Checklist** — a recommendation list built from both the
   service-enumeration results (e.g. "anonymous FTP login SUCCEEDED") and
   a general per-port cheat-sheet (SSH, DNS zone transfer, NFS, MySQL,
   Redis defaults, RDP, etc.).
7. All raw tool output is saved under the output directory
   (`nmap/`, `http/`, `smb/`, `ftp/`), plus a plain-text `SUMMARY.txt`.
8. **Ctrl+C at any point** stops the current scan and saves whatever was
   found so far — it doesn't crash or lose partial results.

## Installation

```bash
# System tools (Ubuntu/Zorin/Debian-based)
sudo apt update
sudo apt install nmap gobuster nikto smbclient ftp dirb

# Optional (only needed if you don't want gobuster):
# sudo apt install ffuf
# or: go install github.com/ffuf/ffuf/v2@latest

# Python dependency
pip install -r requirements.txt --break-system-packages
# (drop --break-system-packages if you're using a venv)
```

The script itself has no hard Python dependency — if `rich` isn't
installed it automatically falls back to plain ANSI-colored output.

## Usage

```bash
python3 ctf_assistant.py
```

You'll be prompted for a target:

```
Enter target IP or hostname: 10.10.11.42
```

The script then runs all phases automatically and writes everything to
`./ctf_results_10.10.11.42_<timestamp>/`.

## Output layout

```
ctf_results_<target>_<timestamp>/
├── SUMMARY.txt                  # plain-text report: ports + recommendations
├── nmap/
│   ├── quick_scan.nmap          # phase 1 raw nmap output
│   └── deep_scan.nmap           # phase 2 raw nmap -sC -sV output
├── http/
│   ├── gobuster_<port>.txt      # (or ffuf_<port>.csv)
│   └── nikto_<port>.txt
├── smb/
│   └── anon_list_shares.txt
└── ftp/
    └── anon_login.txt
```

## Notes / known limitations

- The full-port sweep (`-p-`) on a slow/filtered target can take a while;
  `--min-rate 1000` speeds this up but can be less accurate on lossy
  networks — lower it if you get inconsistent results on a flaky VPN link
  to a CTF platform.
- `gobuster`/`ffuf`/`nikto` are run with a 5-minute timeout per port so one
  slow web target can't stall the whole run.
- Service-specific enumeration matches on **both** the conventional port
  number and the service name Nmap's `-sV` reports, so it still catches
  e.g. an FTP server on a non-standard port — but only if `-sV` correctly
  fingerprinted it in Phase 2.
