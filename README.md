# CTF Recon Assistant

A modular, interactive CLI reconnaissance tool for CTF boxes and lab VMs on
Linux (tested on Ubuntu/Zorin OS). Automates the Nmap sweep → deep scan →
service-specific enumeration workflow, and actively **hunts for flags** in
whatever it finds instead of just listing services — built to actually run
during a timed competition, not just as a demo.

**Only run this against systems you own or are explicitly authorized to
test** (CTF platforms, your own lab VMs, scoped engagements). Unauthorized
scanning is illegal in most jurisdictions.

## What's new in v2 (competition-oriented)

- **Flag detection everywhere.** Every log, every downloaded file, and every
  fetched web page is scanned for `name{...}`-shaped flags automatically —
  live during the scan, and again in a final sweep of the whole output
  directory so nothing slips through.
- **Loot download, not just detection.** Anonymous FTP (via Python's
  built-in `ftplib` — no external `ftp` client needed) and anonymous SMB
  shares are automatically mirrored to `loot/`, and every downloaded file is
  flag-scanned.
- **robots.txt / sitemap.xml are followed, not just fetched.** Whatever they
  disclose (`Disallow:` entries, `<loc>` URLs) is fetched too — this is
  where a lot of CTF flags actually live.
- **Directory brute-force includes extensions** (`php,txt,bak,zip,old,conf,
  config,js,sql,env`) and every 200-OK path found is auto-fetched and
  flag-scanned, not just listed.
- **searchsploit integration** — if installed, every service/version Nmap
  detects gets an automatic offline exploit-db lookup.
- **A "Quick Wins" panel** at the top of the final output: flags found,
  working anonymous access, exploit-db hits — so you don't have to read the
  whole log to find what actually matters.
- **Non-interactive CLI mode** for real competition use — see flags below.
- **`--resume`** — pick back up after a Ctrl+C without re-running completed
  phases.
- **`SUMMARY.md`** alongside `SUMMARY.txt`, for pasting straight into your
  write-up notes.

## Windows / Active Directory enumeration (Phase 3b)

Triggered automatically — no flag needed — whenever any Kerberos (88),
RPC (135), SMB (139/445), LDAP (389/636/3268/3269), RDP (3389), or WinRM
(5985/5986) port is open. A "hard" CTF box is very often Windows/AD, and
that needs a genuinely different playbook than the Linux/web one above:

- **Surfaces what `-sC` already collected but was being thrown away.**
  `smb-os-discovery`, `smb2-security-mode`, and `rdp-ntlm-info` all run by
  default during Phase 2, but the tool previously only flag-scanned the
  raw text and discarded everything else — including OS version, computer
  name, domain, forest, FQDN, SMB signing status, and (via RDP NTLM) the
  domain/hostname fingerprint. All of that is now parsed out and shown as
  Quick Wins, at zero extra scan cost.
- **SMB signing check** — if signing isn't enforced, flags it explicitly as
  an SMB relay opportunity (`ntlmrelayx` + a coercion technique).
- **MS17-010 (EternalBlue) safe-check** (`smb-vuln-ms17-010`) — a positive
  hit is about as big a quick win as this tool can hand you.
- **`smb-enum-shares`/`smb-enum-sessions`** — not in nmap's default script
  category, run explicitly here.
- **`rpcclient` anonymous/null-session enumeration** (`srvinfo`,
  `enumdomusers`, `enumdomgroups`, `querydominfo`, `lsaquery`) — this often
  succeeds even when `smbclient -L` share listing is denied, since it's a
  different RPC pipe. A successful user list is pulled out and surfaced
  directly — gold for password spraying or AS-REP roasting.
- **`enum4linux-ng`** (optional, bonus pass) if installed.
- **RDP encryption/NLA check** (`rdp-enum-encryption`).
- **WinRM recognition** — `Microsoft HTTPAPI httpd` on 5985/5986 is WinRM's
  generic banner, not a real web app; the tool now says so explicitly
  instead of wasting a `--dirb-timeout`-sized chunk of the clock running
  gobuster/nikto against it, and reminds you to try `evil-winrm`/`netexec`
  with any creds found elsewhere — WinRM access is usually an instant shell.
- **Names unknown dynamic RPC ports** (49152–65535, reported `unknown` by
  `-sV`) via `msrpc-enum` instead of leaving them as a dead end — this is
  the exact "port 49670/53559 unknown" situation from a real scan.

New flags: `--no-windows` (skip this phase entirely) and
`--windows-timeout` (default 180s, applies per sub-step).

**Honesty about scope:** this is recon, not exploitation. On a genuinely
hard box, actually retrieving a flag past this point means acting on what
gets surfaced here — spraying the usernames rpcclient found, relaying NTLM
if signing's off, running the EternalBlue exploit if flagged, trying
WinRM with creds picked up elsewhere — not something a recon script can
do for you safely or automatically. Validated by: confirmed `-sV`'s own
`?` uncertainty marker and a clean match empirically on live services;
unit-tested every NSE field-extraction regex against realistic nmap
output (OS/domain/forest/FQDN, SMB signing lines, RDP NTLM fields,
MS17-010 vulnerable/not-vulnerable text) and the `rpcclient` username
regex against a realistic multi-user sample; integration-tested the full
phase against real listening sockets on 445/3389/5985 to confirm every
sub-step (SMB scripts, `rpcclient`, RDP script, WinRM recognition, the
`.done` sentinel) runs and degrades gracefully with no crash when the
protocol isn't actually spoken back. A live Samba/AD server wasn't
spinnable in the sandbox this was built in (socket binding is restricted
there), so full protocol-level behavior (e.g. real `smb-os-discovery`
output, a genuine `rpcclient` user list) couldn't be exercised end-to-end
— worth a first real run with `--windows-timeout` generous and an eye on
the logs under `windows/`.

## Reliability fixes (round 3 — "quietly not doing what you think" bugs)

These target a specific failure class: the tool *looking* like it worked
while actually giving you an incomplete or wrong answer.

- **Confident-but-wrong `-sV` fingerprints, not just empty ones.** nmap
  marks a port-based (unconfirmed) guess with a trailing `?` on the service
  name — e.g. a real test against a raw custom TCP service came back as
  `cbt?`, while a real HTTP server came back as plain `http` with no `?`.
  That marker is now surfaced explicitly, separately from the
  empty/generic case. On top of that, the HTTP phase now does a live
  liveness probe before trusting nmap's guess at all: if the guessed
  scheme (`http`/`https`, itself just a port-number heuristic) gets no
  response, it tries the other scheme and auto-corrects if that one
  works, and if *neither* responds, it bails cleanly with an explicit
  "this may be a misidentified service" recommendation instead of wasting
  a `--dirb-timeout`-sized chunk of the clock running gobuster against a
  dead end. All three cases (unconfirmed custom protocol, confidently-
  wrong scheme, real HTTP) were tested against live services.
- **`--resume` no longer trusts a truncated result.** Every phase that can
  hit a timeout (gobuster/ffuf/nikto/vhost fuzzing, SMB share downloads)
  now only gets marked complete (a `.done` sentinel next to its log) when
  it actually finished — a timeout, a crash, or an interrupted run leaves
  no sentinel, so `--resume` correctly detects and re-runs it instead of
  silently treating a partial gobuster log as a finished one. Verified by
  forcing a real timeout, confirming no sentinel was written, and
  confirming `--resume` then re-ran exactly that phase and printed a
  "looks incomplete, re-running" notice. `quick_scan.done`/`deep_scan.done`
  are likewise only written on a clean `rc == 0` exit, not merely "the
  subprocess call didn't raise."
- **A gobuster ANSI-code bug, generalized.** gobuster emits color escape
  codes even in piped output on some versions, which was corrupting parsed
  paths. Fixed two ways: `--no-color` on every gobuster invocation (the
  real fix) plus a defensive strip-before-parse on both the gobuster and
  ffuf output paths (belt and suspenders, and it'll catch the same class
  of bug if a future tool does this too).
- **Rich markup was silently eating bracketed text.** `console.print` and
  `Table` cells interpret `[...]` as inline style tags by default — which
  meant every `[resume]`/`[i]` prefix in this tool's own log messages was
  being silently swallowed (confirmed empirically: `"[resume] ..."`
  rendered as `" ..."` with the tag gone), and, more seriously, a **flag
  value pulled from the target box** could have bracket-shaped content
  silently stripped before you ever saw it, since flags are untrusted
  external data displayed in a `Table`. Fixed by constructing the console
  with `markup=False` (styling still applied correctly via the explicit
  `style=` kwarg everywhere) and switching the two places that genuinely
  needed inline styling (`section()` headers, the tool-checklist
  READY/MISSING cells) to `Text(..., style=...)` objects instead of markup
  strings. Verified with a flag deliberately crafted to contain
  `[bold]...[/bold]`-shaped content — it now displays byte-for-byte
  correctly in the console, `SUMMARY.txt`, and `SUMMARY.md`.

## What it does

1. **Target input & validation** — `-t`/`--target` non-interactively, or
   prompts if omitted. Validates and resolves hostnames, and creates a
   timestamped output directory (`./ctf_results_<target>_<timestamp>/`).
2. **Tool checklist** — checks for `nmap`, `gobuster`/`ffuf`, `nikto`,
   `smbclient`, `searchsploit` and shows a READY/MISSING/OPTIONAL table.
   Missing tools cause their specific phase to be skipped, not a crash.
3. **Phase 1 — Quick scan**: full 65535-port sweep by default, or
   `--fast` for top-1000, or skip it entirely with `-p/--ports` if you
   already know what's open (saves real time in a timed event).
4. **Phase 1b — Optional UDP sweep** (`--udp`, needs root/sudo for
   accurate results) — catches SNMP/TFTP/NTP, which people miss constantly.
5. **Phase 2 — Deep scan**: `-sC -sV` against exactly the ports found open.
   Flags a service with a weak/generic fingerprint (no version, or a
   name like `tcpwrapped`) so you remember to check it by hand with
   `curl`/`nc` — `-sV` guesses wrong often enough on non-standard ports
   that this tool's own auto-enumeration would otherwise silently miss it.
6. **searchsploit pass** over every detected service/version, if installed.
7. **Phase 3 — Service-specific enumeration + loot + flag scanning**:
   - **HTTP/HTTPS** → common CTF paths fetched directly; robots.txt/
     sitemap.xml disclosures followed; `gobuster dir` (or `ffuf`) with
     extensions; every 200-OK path auto-fetched and flag-scanned; `nikto`
     if available; optional **`--vhost`** Host-header brute-forcing.
   - **SMB** → anonymous share listing, then every accessible share is
     downloaded into `loot/smb/<share>/` and flag-scanned.
   - **FTP** → anonymous login via `ftplib`, then a recursive download of
     the accessible tree into `loot/ftp/`, flag-scanned as it goes.
8. **Quick Wins panel**, then the general **Next Steps checklist** (a
   per-port cheat-sheet: SSH, DNS zone transfer, NFS, MySQL, Redis
   defaults, RDP, SNMP, TFTP, etc.).
9. A final sweep of the whole output directory for anything flag-shaped
   that the per-phase scanning missed.
10. **Ctrl+C at any point** saves partial results and prints the exact
    `--resume` command to pick back up later.

## Installation

```bash
# System tools (Ubuntu/Zorin/Debian-based)
sudo apt update
sudo apt install nmap gobuster nikto smbclient dirb

# Optional (only needed if you don't want gobuster):
# sudo apt install ffuf
# or: go install github.com/ffuf/ffuf/v2@latest

# Optional — searchsploit isn't in the standard Ubuntu/Zorin repos.
# Either install Kali's exploitdb package, or:
git clone https://gitlab.com/exploit-database/exploitdb.git ~/exploitdb
ln -s ~/exploitdb/searchsploit /usr/local/bin/searchsploit
cp ~/exploitdb/.searchsploit_rc ~/.searchsploit_rc

# Python dependency
pip install -r requirements.txt --break-system-packages
# (drop --break-system-packages if you're using a venv)
```

The script itself has no hard Python dependency — if `rich` isn't
installed it automatically falls back to plain ANSI-colored output.
Anonymous FTP checks use Python's built-in `ftplib`, so no external `ftp`
client is required at all.

## Usage

Interactive (original behavior):
```bash
python3 ctf_assistant.py
```

Non-interactive, for actual competition use:
```bash
# Full run, all defaults
python3 ctf_assistant.py -t 10.10.11.42

# You already ran a quick nmap -F yourself and know the ports — skip Phase 1
python3 ctf_assistant.py -t 10.10.11.42 -p 80,22,445

# Lossy HTB/THM VPN — slow down the sweep
python3 ctf_assistant.py -t 10.10.11.42 --min-rate 300

# Time-pressured: top-1000 ports only, tighter tool timeouts
python3 ctf_assistant.py -t 10.10.11.42 --fast --dirb-timeout 120 --nikto-timeout 60

# Everything: UDP sweep, thorough wordlist, vhost fuzzing, custom wordlist
python3 ctf_assistant.py -t 10.10.11.42 --udp --thorough --vhost \
    --vhost-domain target.htb --wordlist /opt/seclists/raft-medium-directories.txt

# Ctrl+C'd out of a run? Pick back up without re-doing finished phases:
python3 ctf_assistant.py -t 10.10.11.42 --resume ./ctf_results_10.10.11.42_20260101_120000
```

Full flag reference: `python3 ctf_assistant.py --help`

| Flag | Purpose |
|---|---|
| `-t/--target` | Target IP/hostname, skips the interactive prompt |
| `-p/--ports` | Comma-separated ports — skips Phase 1's full sweep entirely |
| `--fast` | Phase 1 scans top-1000 ports instead of all 65535 |
| `--min-rate` | Nmap `--min-rate` (default 1000) — lower on lossy VPNs |
| `--udp` | Also run a quick UDP sweep (needs root/sudo) |
| `--udp-top-ports` | How many UDP ports to check (default 50) |
| `--thorough` | Bigger wordlist, more exhaustive HTTP enumeration |
| `--wordlist` | Exact wordlist path for gobuster/ffuf, overrides auto-detect |
| `--dirb-timeout` | Per-port gobuster/ffuf timeout in seconds (default 300) |
| `--nikto-timeout` | Per-port nikto timeout in seconds (default 150) |
| `--vhost` | Brute-force virtual hosts via the Host header |
| `--vhost-domain` | Base domain for `--vhost` (required if target is a bare IP) |
| `--vhost-wordlist` | Wordlist for `--vhost` (small built-in default otherwise) |
| `--no-http` / `--no-smb` / `--no-ftp` | Skip that phase entirely |
| `-o/--output-dir` | Exact output directory instead of an auto timestamped one |
| `--no-windows` | Skip the Windows/AD enumeration phase (Phase 3b) |
| `--windows-timeout` | Per-sub-step timeout for Phase 3b (default 180) |
| `--resume DIR` | Resume into an existing output dir, skipping finished phases |

## Output layout

```
ctf_results_<target>_<timestamp>/
├── SUMMARY.txt / SUMMARY.md     # flags found, quick wins, ports, next steps
├── nmap/
│   ├── quick_scan.nmap
│   ├── deep_scan.nmap
│   └── udp_scan.nmap            # if --udp
├── searchsploit/
│   └── port_<port>.txt          # if searchsploit installed
├── http/
│   ├── fetched_<path>.txt       # every 200-OK path, flag-scanned
│   ├── gobuster_<port>.txt      # (or ffuf_<port>.csv)
│   ├── nikto_<port>.txt
│   └── vhost_<port>.txt         # if --vhost
├── smb/
│   └── anon_list_shares.txt
├── ftp/
│   └── anon_login.txt
├── loot/
│   ├── ftp/                     # everything downloaded from anon FTP
│   └── smb/<share>/             # everything downloaded from anon SMB
├── windows/                      # Phase 3b — Windows/AD enumeration
│   ├── smb_scripts.nmap          # smb-enum-shares/sessions, smb-vuln-ms17-010
│   ├── rpcclient_anon.txt        # anonymous/null-session rpcclient output
│   ├── enum4linux-ng.txt         # if enum4linux-ng installed
│   ├── rdp_scripts.nmap          # rdp-enum-encryption
│   └── msrpc_enum_<port>.nmap    # per unknown dynamic RPC port
└── *.done                       # completion sentinels (nmap/, http/, smb/, ftp/, windows/) —
                                  # --resume only trusts a phase if its sentinel exists
```

## Notes / known limitations

- The full-port sweep (`-p-`) on a slow/filtered target can take a while;
  `--min-rate` speeds this up but can misbehave on lossy networks — lower
  it (e.g. `--min-rate 300`) if you get inconsistent results on a flaky
  VPN link to a CTF platform.
- `-sV`'s service fingerprinting is still a best-effort guess, and the
  tool now checks it two ways: an empty/generic name (`tcpwrapped`, no
  version) is flagged, and so is nmap's own trailing-`?` "this is an
  unconfirmed guess" marker — both get an explicit reminder to verify by
  hand with `curl`/`nc`. The HTTP phase additionally does its own live
  probe before trusting the guess (see "Reliability fixes" above), so a
  wrong `http`/`https` guess self-corrects and a service that isn't
  really HTTP at all gets caught even when nmap was fully confident.
- `--resume` now checks a `.done` sentinel per phase, written only on a
  clean, complete run — a phase that hit a timeout, crashed, or was
  interrupted correctly gets re-run rather than trusted. This closes the
  main way `--resume` could previously have silently returned an
  incomplete result.
- `--vhost` uses `gobuster vhost` mode; there's no automatic ffuf
  equivalent wired up (the tool prints the manual `ffuf -H "Host: ..."`
  command if gobuster isn't available).
- Before the event: tag a known-good commit/branch of this script so a
  last-minute tweak under time pressure can't break the tool you're
  relying on mid-competition. Copy that frozen file to the competition
  machine rather than editing in place.
