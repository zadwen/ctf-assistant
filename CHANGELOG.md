# 2.1.0

- Added modular offline evidence engine and --analyze CLI.
- Added contextual 32-hex machine-flag candidates and configurable event prefixes.
- Added bounded URL/HTML/Base64/hex/ROT13 decoding, UTF-16 support, ZIP/GZIP inspection.
- Added confidence, source, transformation and line provenance with JSON export.
- Added offline single-host Nmap XML import; main live scans now save XML too.
- Added session target/options/version matching for resume and missing-log checks.
- Restored UDP scan results on resume; retain open|filtered uncertainty.
- Fixed TCP/UDP port-number collisions and prevented TCP enumerators using UDP ports.
- Preserved bytes captured by subprocess timeouts and handled invalid output encoding.
- Enforced FTP size limits during transfer and rejected escaping FTP/SMB names.
- Limited Python-discovered HTTP fetches/redirects to their original origin.
- Avoided colliding/overlong saved HTTP filenames with a short URL digest.
- Corrected SMB download success reporting for nonzero exit statuses.
- Added regression/integration tests, setup instructions and official references.

Existing network enumeration is retained. The release is an evidence/reliability
upgrade, not an automatic exploitation engine or guaranteed flag solver.
