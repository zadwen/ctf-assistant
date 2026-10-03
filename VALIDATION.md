# v2.2 validation record

On 2026-10-03, all 33 unittest cases passed in 6.803 seconds. All four application
modules also passed Python compilation; the CLI --version reports 2.2.0.

The 19 v2.1 regression tests cover encoded/contextual flag detection, archives,
XML import, offline network-call blocking, TCP/UDP separation, timeout output,
resume validation, and FTP/HTTP boundary handling.

The 14 new tests exercise:
- HTML, robots, comment, JavaScript, source-map and response-header evidence.
- Inline source maps and sitemap links.
- Form inventory with no form submissions.
- Refusing cross-origin references and redirect destinations.
- Soft-404 classification without discarding candidate evidence.
- Request caps including baseline probes/redirects, depth and response-size caps.
- Redirect loops and duplicate-body relative-link handling.
- URL validation and normalization.
- Web-only CLI reports and evidence-driven prioritization.
- Cumulative crawler time budgets across calls and expired-budget behavior.
- Automatic crawler integration into the existing IP HTTP phase.

Network tests used HTTP servers bound only to 127.0.0.1 with synthetic flags.
Loopback tests were run with permission to open local sockets after the default
sandbox blocked listening sockets. No external or competition targets were used.

Nmap/Gobuster/ffuf/Nikto/SMB/FTP tool compatibility, authenticated web apps,
HTTPS live behavior, and actual platform flag acceptance were not tested.
No exhaustive security audit or guaranteed challenge-solving claim is made.
