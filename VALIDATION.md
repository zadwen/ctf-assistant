# Validation record

19 unittest cases passed on 2026-10-03 using Python standard-library execution.
The suite includes mocked live scan/resume orchestration, offline CLI network-call
blocking, XML host selection and entity rejection, flag formats and encodings,
ZIP/GZIP/UTF-16, archive limits, symlink/report skipping, provenance deduplication,
timeout bytes, TCP/UDP separation, HTTP discovery/redirect scope, CLI validation,
session mismatch, missing resume logs, FTP traversal, and FTP streaming size caps.

Both Python modules also passed py_compile; CLI --help was checked.
No live HTB/THM targets or external enumeration tools were exercised.
