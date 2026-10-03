# CTF Recon Assistant 2.2.0

By **zadwen**. An upgrade of the supplied v2.0 project for authorized CTF/lab work.
Python **3.10+**. Keep all four `ctf_*.py` modules together.

This release adds automatic web mapping and a prioritized evidence checklist to the existing IP workflow. It does not
solve every challenge, validate flags with a platform, submit flags, or execute
exploits automatically. The existing network enumeration workflow remains available.

## What is new in 2.2

Entering an assigned IP still works. On HTTP services, the tool now automatically:

- Walks same-origin HTML links and JavaScript references, plus robots/sitemap paths.
- Reads external and inline source maps, including embedded original source.
- Looks for flags in response bodies, source-map content, and response headers.
- Inventories forms, parameter names, and useful HTML comments for manual review.
- Compares two nonexistent-page responses to flag likely catch-all/soft-404 pages.
- Records equal response bodies while still resolving their relative links correctly.
- Writes `NEXT_STEPS.md`, ordered by observed evidence, and `WEB_MAP.md`.

No additional Python package is needed. This is not an automatic exploit engine.

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

### Scan just a web challenge (no Nmap required)

```bash
python3 ctf_assistant.py --web-url http://YOUR_LAB_HOST:8080/ -o results/web
```

Replace the placeholder with the assigned challenge URL. This mode uses only the
new mapper, without Gobuster, Nikto, or other subprocesses. It requires a new/empty
output directory. The URL may include a starting path; traversal is scoped to the
whole origin, not limited to that path. `--web-url` cannot be mixed with `--target`,
`--resume`, offline inputs, `--no-crawl`, or `--no-http`.

The normal IP workflow enables the mapper without any extra flags:

```bash
python3 ctf_assistant.py -t 10.10.10.10 --fast -o results/automatic
```

To spend more time on web discovery:

```bash
python3 ctf_assistant.py -t 10.10.10.10 --fast \
  --web-pages 150 --web-depth 4 --web-seconds 240 -o results/deeper
```

Default per-origin mapper limits are **60 requests, depth 3, 120 seconds of
cumulative mapper runtime, 0.1 second between request starts, 1 MiB per response,
and 16 MiB counted body bytes**. Baseline probes and redirects count as requests.
GZIP expansion is bounded and counts toward the byte limit. The time limit does
not include separate enumeration tools; an in-flight read may finish after the
budget by up to its socket timeout. Analysis work between reads may also overrun.
The limits do not cap Nmap/Gobuster/Nikto or legacy SMB/FTP enumeration.

`--no-crawl` keeps the v2.1 HTTP path checks. `--no-http` skips HTTP enumeration.
The web mapper sends GET requests only, does not submit forms, and does not execute
JavaScript. Action-like paths such as logout/delete/reset are recorded but skipped;
GET-only behavior cannot guarantee an application has no side effects.

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

### Resume a v2.2 live scan

```bash
python3 ctf_assistant.py -t 10.10.10.10 --fast --resume results/box
```

Repeat the original scan options. `session.json` binds the target, version, and
options to the directory. Changed settings or another target require a fresh
directory. v2.0/v2.1 directories can be analyzed using `--analyze`, but cannot be
resumed by v2.2 because metadata is missing or the tool version differs. Completion markers need matching logs.
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
- `REPORT.json`: schema version 2; adds web results and ranked next steps to v2.1 fields.
- `NEXT_STEPS.md`: evidence-based checklist (candidate flags, exposed source, redirects, forms).
- `WEB_MAP.md`: fetched URLs, status codes, discovery sources, duplicates, forms, and warnings.
- `web/<origin-id>/crawl.json`: detailed per-origin crawl results, restored during normal resume.
- `web/<origin-id>/bodies/`: saved response bytes; never executed automatically.
- Original network logs and downloaded artifacts remain in the output directory.

Candidates are deduplicated by value/source/transformation/line. One flag may have
multiple evidence locations. `candidate_count` counts unique strings including
low-confidence guesses, and `flags_verified` is always false.
Generated report filenames, including crawl.json and the new Markdown reports, are excluded from artifact analysis to prevent reports
from being mistaken for fresh challenge evidence. JSON writes use an atomic rename.

## Reading the web evidence

Start with `NEXT_STEPS.md`. It ranks candidates ahead of source-map/backup/hostname
leads, followed by comments, endpoints, forms, and uncertain ports. Rankings do not
prove a vulnerability; they identify evidence worth checking first. Low-confidence
flag guesses stay in the full evidence report.

A **soft-404** classification requires two matching, lightly normalized responses
to random nonexistent paths. It reduces false backup/config alerts; it is not a
universal error-page detector. Bodies are still scanned for candidates even when
classified as soft-404. Dynamic pages can evade this comparison.

Source-map `sourcesContent` is inspected as data. Source names cannot write files
or escape the output directory. Missing `sourcesContent` is not automatically
recovered from a repository. JavaScript endpoint discovery recognizes a limited
set of literal fetch/axios/path patterns, not dynamically generated URLs.

Cross-origin redirects become hostname leads. For an IP redirecting to a `.htb`
hostname, check the competition scope and configure that lab hostname yourself,
then use `--web-url` explicitly. The tool does not change `/etc/hosts`.

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
- Existing live HTTP fetches and the new mapper accept self-signed TLS certificates for labs.
- The mapper caps 2,000 discovered URLs, three query variants per path, five followed
  redirect hops, 20 source maps, and 100 embedded sources per map. Images/fonts/video
  and PDFs are not crawled. Depth-limited traversal is not an exhaustive site audit.
- No login/session automation or supplied authentication headers are implemented.
  Applications requiring browser execution or authentication may need manual work.
- FTP enforces the existing 3 MiB download cap even without server SIZE support and
  rejects escaping local paths. SMB retains its external smbclient recursive
  download behavior: the offline analysis budget is not an SMB download-size cap.
- Existing service recommendations and version lookups are leads, not confirmed
  vulnerabilities. Nonzero Gobuster/ffuf/Nikto exits now prevent HTTP success markers; other
  legacy phase markers may not capture every external-tool failure. IPv6-specific behavior of the legacy live workflow is not upgraded.
- `--no-http`, `--no-smb`, `--no-ftp`, and `--no-windows` remain available to skip
  live enumeration phases. Network scanning is limited to explicitly assigned labs.

## Validation

```bash
python3 -m unittest discover -s tests -v
```

Tests use synthetic flags, archives, XML, mocked subprocesses, temporary directories,
and HTTP challenge servers bound only to 127.0.0.1. No HTB/THM target is contacted
by the tests. The web integration tests need permission to open loopback sockets. Live external-tool
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

5. [TryHackMe: Walking An Application](https://tryhackme.com/room/walkinganapplication)
   describes reviewing source and JavaScript as part of application exploration.
6. [HTB Academy: Information Gathering — Web Edition](https://academy.hackthebox.com/course/preview/information-gathering---web-edition)
   lists web crawling and HTTP-header analysis in its public course overview.

`README_v2_REFERENCE.md` is the original documentation preserved for reference;
this README takes precedence for changed v2.2 behavior.
