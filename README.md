# CTF Recon Assistant 2.1.0

By **zadwen**. An upgrade of the supplied v2.0 project for authorized CTF/lab work.
Python **3.10+**. Keep `ctf_assistant.py` and `ctf_evidence.py` together.

This release improves evidence collection and candidate discovery. It does not
solve every challenge, validate flags with a platform, submit flags, or execute
exploits automatically. The existing network enumeration workflow remains available.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 ctf_assistant.py --help
```

`rich` is optional; the program works using the Python standard library without it.
Live enumeration uses locally installed tools such as Nmap, Gobuster/ffuf,
Nikto, and smbclient. The existing checklist identifies missing tools.
Offline analysis requires none of those tools and makes no network requests.

### Scan your assigned lab machine

Replace `10.10.10.10` with the target assigned to you in the lab.

```bash
python3 ctf_assistant.py -t 10.10.10.10 --fast -o results/box
```

To check all TCP ports, omit `--fast`. To enumerate known ports:

```bash
python3 ctf_assistant.py -t 10.10.10.10 -p 22,80,445 -o results/known-ports
```

Live scans retain HTTP/SMB/FTP and Windows enumeration, exploit-database lookups,
and service recommendations. Collected artifacts pass through the new evidence
engine. Main quick/deep/UDP Nmap scans now also save XML alongside readable logs.

### Analyze challenge files, downloads, or terminal transcripts offline

```bash
python3 ctf_assistant.py --analyze ./challenge.zip ./loot ./terminal.txt -o results/evidence
```

Inputs must exist; use just the paths you actually have. A directory is traversed
recursively. Local analysis does not require a target. The archive itself is not
executed or extracted. File content that you obtain manually, including shell
transcripts, can be analyzed the same way.

### Import an existing Nmap report offline

```bash
python3 ctf_assistant.py --import-nmap scan.xml -o results/imported
python3 ctf_assistant.py --import-nmap scan.xml -t 10.10.10.10 --analyze ./loot -o results/combined
```

Use XML from Nmap's `-oX` option. `--target` selects an exact address/hostname in
multi-host XML, with no DNS resolution. Import preserves service versions, TLS
tunnels, TCP/UDP identity, open versus open|filtered state, and NSE output.
Import is analysis-only; it does not launch enumeration against imported hosts.

### Event-specific formats

```bash
python3 ctf_assistant.py --analyze ./challenge.zip --flag-prefix MYCTF -o results/event
```

Repeat `--flag-prefix` for more event prefixes. Matching is case-insensitive for
prefix recognition; the actual flag value preserves its original case.
Recognized prefixes include HTB, THM, flag, CTF, picoCTF, and root.

### Resume a v2.1 live scan

```bash
python3 ctf_assistant.py -t 10.10.10.10 --fast --resume results/box
```

Repeat the original scan options. `session.json` binds the target, version, and
options to the directory. Changed settings or another target require a fresh
directory. v2.0 directories can be analyzed using `--analyze`, but cannot be
resumed because they lack this metadata. Completion markers need matching logs.
The UDP log is loaded when its phase is resumed. Resume does not prove the remote
machine is unchanged: use a new directory after a machine reset or reassignment.

## Detection and confidence

| Candidate | Treatment |
|---|---|
| Recognized `PREFIX{...}` | High heuristic confidence |
| 32 hexadecimal characters in user.txt/root.txt/flag.txt/proof.txt/local.txt, or immediately after a flag/user/root/proof/local label | Medium confidence; may still be a checksum |
| Other `NAME{...}` in raw text | Low confidence; may be code/template content |
| Unlabelled 32-hex string | Ignored unless `--include-hashes`; then low confidence |

HTB machine flags use 32 hexadecimal characters, unlike many brace-formatted
challenge flags [1]. Filename and label context reduces checksum false positives.
High/medium candidates appear in the short summary; all confidence levels appear
in `REPORT.json` and the Markdown evidence table. Confidence is not validation.

The detector tries URL encoding, HTML entities, Base64 (including URL-safe), hex,
and ROT13, up to two transformation levels. UTF-16 and UTF-8 artifact content are
supported. Binary files can yield embedded text, but there is no disassembler,
steganography solver, PDF parser, password cracker, or general cryptographic solver.
Decoded line numbers refer to the decoded view, not an original byte offset.

## Reports

- `SUMMARY.txt`: candidate summary, quick wins, services, recommendations, warnings.
- `SUMMARY.md`: readable summary plus confidence, source, transformation, and line.
- `REPORT.json`: schema version 1; candidates, ports/states, warnings, and metadata.
- Original network logs and downloaded artifacts remain in the output directory.

Candidates are deduplicated by value/source/transformation/line. One flag may have
multiple evidence locations. `candidate_count` counts unique strings including
low-confidence guesses, and `flags_verified` is always false.
Generated report filenames are excluded from artifact analysis to prevent reports
from being mistaken for fresh challenge evidence. JSON writes use an atomic rename.

## Limits and compatibility

- Artifact analysis: 3 MiB per file/member, 24 MiB total bytes consumed per scanner,
  and 500 files/members; archive input and decoded members both count.
- ZIP and GZIP supported, at most two archive levels. Encrypted ZIP members are
  skipped. Warnings identify skipped large/encrypted entries and budget limits.
- Per text: at most 64 decoding nodes, two transformation levels, 1,000 matches,
  and bounded encoded-token sizes. These are heuristics, not exhaustive decoding.
- Symlink files/directories are not followed by artifact analysis. ZIP member names
  are provenance only; even traversal names are never written to disk.
- Automatic Python HTTP fetches and redirects stay on the original scheme, host,
  and port. Cross-origin redirects (including HTTP-to-HTTPS or IP-to-hostname) are
  blocked. Review a lab redirect manually and select the correct target origin.
  This rule does not constrain independent external tools such as Nikto/Gobuster.
- Existing live HTTP fetches still accept self-signed TLS certificates for labs.
- FTP enforces the existing 3 MiB download cap even without server SIZE support and
  rejects escaping local paths. SMB retains its external smbclient recursive
  download behavior: the offline analysis budget is not an SMB download-size cap.
- Existing service recommendations and version lookups are leads, not confirmed
  vulnerabilities. Some legacy phase markers may not capture every external-tool
  failure. IPv6-specific behavior of the legacy live workflow is not upgraded.
- `--no-http`, `--no-smb`, `--no-ftp`, and `--no-windows` remain available to skip
  live enumeration phases. Network scanning is limited to explicitly assigned labs.

## Validation

```bash
python3 -m unittest discover -s tests -v
```

Tests use synthetic flags, archives, XML, mocked network/subprocess calls, and local
temporary directories. No HTB/THM target is contacted by the tests. Live external-tool
compatibility and platform flag acceptance have not been tested in this environment.

## References

These are design references, not claims of affiliation or platform certification.

1. [Hack The Box: Machine Submission Requirements — Flag Requirements](https://help.hackthebox.com/en/articles/5307061-machine-submission-requirements)
   documents machine flag format and user/root flag locations.
2. [TryHackMe: Nmap Post Port Scans](https://tryhackme.com/room/nmap04)
   describes service detection, NSE, and saving scan results in its public overview.
   Premium task content was not accessed.
3. [Nmap: XML Output](https://nmap.org/book/output-formats-xml-output.html)
   documents XML output for machine-readable analysis.
4. [Hack The Box: How to Play Challenges](https://help.hackthebox.com/en/articles/5185436-how-to-play-challenges)
   explains challenge files and manual submission.

`README_v2_REFERENCE.md` is the original documentation preserved for reference;
this README takes precedence for changed v2.1 behavior.
