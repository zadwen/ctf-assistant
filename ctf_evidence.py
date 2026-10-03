"""Bounded, offline evidence analysis for CTF Assistant (standard library only)."""
from __future__ import annotations

import base64
import codecs
import gzip
import hashlib
import html
import io
import json
import re
import zipfile
from collections import deque
from pathlib import Path
from urllib.parse import unquote
import xml.etree.ElementTree as ET

MAX_FILE = 3 * 1024 * 1024
MAX_TOTAL = 24 * 1024 * 1024
MAX_FILES = 500
KNOWN_PREFIXES = {'htb', 'thm', 'flag', 'ctf', 'picoctf', 'root'}
BRACED = re.compile(r'\b[A-Za-z][A-Za-z0-9_]{0,31}\{[^{}\r\n]{1,256}\}')
HASH = re.compile(r'(?<![A-Za-z0-9])[a-fA-F0-9]{32}(?![A-Za-z0-9])')
FLAG_SOURCE = re.compile(r'(?:^|[/\\\s:!])(?:user|root|flag|proof|local)\.txt(?:$|[\s?\]\'"#])', re.I)
REPORT_NAMES = {'SUMMARY.txt', 'SUMMARY.md', 'REPORT.json', 'CANDIDATES.md', 'session.json'}


def detect(text, source='', prefixes=(), include_hashes=False):
    """Return candidates, preserving case, line and decoding provenance.

    Confidence describes a heuristic, never platform validation. Hashes only
    enter the normal candidate list with a flag filename or nearby label.
    """
    known = KNOWN_PREFIXES | {p.lower() for p in prefixes}
    queue = deque([(text[:MAX_FILE], 'raw', 0)])
    seen_text, seen_findings, findings = set(), set(), []
    nodes = 0
    while queue and nodes < 64:
        value, transform, depth = queue.popleft()
        fingerprint = hashlib.sha256(value.encode('utf-8', errors='replace')).digest()
        if fingerprint in seen_text:
            continue
        seen_text.add(fingerprint)
        nodes += 1
        for pattern, kind in ((BRACED, 'braced'), (HASH, 'hex32')):
            for match in pattern.finditer(value):
                candidate = match.group()
                line_start = value.rfind('\n', 0, match.start()) + 1
                nearby = value[max(line_start, match.start() - 80):match.start()]
                if kind == 'hex32':
                    contextual = bool(FLAG_SOURCE.search(source) or re.search(
                        r'\b(?:flag|user|root|proof|local)\s*(?:flag)?\s*[:=]\s*$', nearby, re.I))
                    if not contextual and not include_hashes:
                        continue
                    confidence = 'medium' if contextual else 'low'
                    reason = '32 hex characters with flag context' if contextual else 'Unlabelled hash; may be a checksum'
                else:
                    recognized = candidate.split('{', 1)[0].lower() in known
                    if not recognized and transform != 'raw':
                        continue
                    confidence = 'high' if recognized else 'low'
                    reason = 'Recognized flag prefix' if recognized else 'Unknown prefix; may be code or a template'
                key = (candidate, transform, value.count('\n', 0, match.start()) + 1)
                if key in seen_findings:
                    continue
                seen_findings.add(key)
                findings.append(dict(value=candidate, source=source, confidence=confidence,
                                     kind=kind, transform=transform, line=key[2], reason=reason))
                if len(findings) >= 1000:
                    return findings
        if depth >= 2:
            continue
        variants = [(unquote(value), 'url'), (html.unescape(value), 'html'),
                    (codecs.decode(value, 'rot_13'), 'rot13')]
        # Tokens only: do not decode arbitrary entire documents or execute content.
        for token in re.finditer(r'(?<![\w+/=-])[A-Za-z0-9+/_-]{12,4096}={0,2}(?![\w+/=-])', value):
            if len(variants) >= 24:
                break
            try:
                raw = token.group()
                decoded = base64.b64decode(raw + '=' * (-len(raw) % 4), altchars=b'-_', validate=True).decode('utf-8')
                if decoded and all(c.isprintable() or c in '\r\n\t' for c in decoded):
                    variants.append((decoded, 'base64'))
            except (ValueError, UnicodeError):
                pass
        for token in re.finditer(r'\b(?:[a-fA-F0-9]{2}){6,2048}\b', value):
            if len(variants) >= 32:
                break
            try:
                decoded = bytes.fromhex(token.group()).decode('utf-8')
                if decoded and all(c.isprintable() or c in '\r\n\t' for c in decoded):
                    variants.append((decoded, 'hex'))
            except (ValueError, UnicodeError):
                pass
        for decoded, name in variants:
            if decoded != value and len(queue) < 64:
                queue.append((decoded, transform + ' > ' + name, depth + 1))
    return findings


class ArtifactScanner:
    """Read files and archive members without extracting or following symlinks."""
    def __init__(self, prefixes=(), include_hashes=False):
        self.prefixes = prefixes
        self.include_hashes = include_hashes
        self.findings = []
        self.warnings = []
        self.bytes_read = 0
        self.files_read = 0

    def scan(self, paths):
        for raw_path in paths:
            path = Path(raw_path)
            if path.is_symlink():
                self.warnings.append(f'Skipped symlink: {path}')
                continue
            if not path.exists():
                self.warnings.append(f'Input does not exist: {path}')
                continue
            files = path.rglob('*') if path.is_dir() else [path]
            for item in files:
                if self.files_read >= MAX_FILES or self.bytes_read >= MAX_TOTAL:
                    self.warnings.append('Analysis budget reached; some evidence was not scanned')
                    return self.findings
                if item.is_symlink() or not item.is_file() or item.name in REPORT_NAMES:
                    continue
                try:
                    if item.stat().st_size > MAX_FILE:
                        self.warnings.append(f'Skipped oversized file: {item}')
                        continue
                    with item.open('rb') as stream:
                        data = stream.read(MAX_FILE + 1)
                    self._consume(data, str(item), 0)
                except (OSError, ValueError) as exc:
                    self.warnings.append(f'{item}: {exc}')
        return self.findings

    def _consume(self, data, source, depth):
        if len(data) > MAX_FILE or self.bytes_read + len(data) > MAX_TOTAL or self.files_read >= MAX_FILES:
            self.warnings.append(f'Skipped at analysis limit: {source}')
            return
        self.bytes_read += len(data)
        self.files_read += 1
        if data.startswith(b'PK\x03\x04') or data.startswith(b'\x1f\x8b'):
            if depth >= 2:
                self.warnings.append(f'Archive nesting limit: {source}')
                return
            try:
                if data.startswith(b'PK'):
                    with zipfile.ZipFile(io.BytesIO(data)) as archive:
                        members = archive.infolist()
                        if len(members) > MAX_FILES:
                            self.warnings.append(f'Archive member limit: {source}')
                        for member in members[:MAX_FILES]:
                            if self.files_read >= MAX_FILES or self.bytes_read >= MAX_TOTAL:
                                self.warnings.append(f'Archive analysis budget reached: {source}')
                                break
                            if member.is_dir():
                                continue
                            label = source + '!' + member.filename
                            if member.file_size > MAX_FILE or member.flag_bits & 1:
                                self.warnings.append(f'Skipped oversized/encrypted member: {label}')
                                continue
                            with archive.open(member) as stream:
                                child = stream.read(min(MAX_FILE, MAX_TOTAL - self.bytes_read) + 1)
                            self._consume(child, label, depth + 1)
                else:
                    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                        child = stream.read(min(MAX_FILE, MAX_TOTAL - self.bytes_read) + 1)
                    self._consume(child, source + '!gzip', depth + 1)
            except (OSError, ValueError, EOFError, RuntimeError, zipfile.BadZipFile, NotImplementedError) as exc:
                self.warnings.append(f'Cannot read archive {source}: {exc}')
            return
        texts = [(data.decode('utf-8', errors='replace'), '')]
        if data.startswith((b'\xff\xfe', b'\xfe\xff')):
            texts.append((data.decode('utf-16', errors='replace'), 'utf16 > '))
        elif b'\x00' in data[:256]:
            texts.extend((data.decode(codec, errors='replace'), codec + ' > ')
                         for codec in ('utf-16-le', 'utf-16-be'))
        for text, prefix in texts:
            for finding in detect(text, source, self.prefixes, self.include_hashes):
                finding['transform'] = prefix + finding['transform']
                self.findings.append(finding)


def parse_nmap(path, target=None):
    """Import exactly one host, keeping protocol, state, TLS and NSE evidence."""
    path = Path(path)
    if path.stat().st_size > MAX_TOTAL:
        raise ValueError('Nmap XML exceeds 24 MiB')
    data = path.read_bytes()
    if b'<!ENTITY' in data.upper() or b'<!DOCTYPE' in data.upper() and b'[' in data:
        raise ValueError('XML entities/internal DTD subsets are not accepted')
    root = ET.fromstring(data)
    if root.tag != 'nmaprun':
        raise ValueError('Expected an Nmap XML report')
    hosts = root.findall('host')
    if target:
        hosts = [h for h in hosts if target in
                 [a.get('addr') for a in h.findall('address')] +
                 [n.get('name') for n in h.findall('hostnames/hostname')]]
    if len(hosts) != 1:
        raise ValueError('Select exactly one XML host with --target (no DNS lookup is performed)')
    host = hosts[0]
    addresses = [a.get('addr') for a in host.findall('address') if a.get('addrtype') in ('ipv4', 'ipv6')]
    ports = []
    for node in host.findall('ports/port'):
        state = node.find('state')
        if state is None or state.get('state') not in ('open', 'open|filtered'):
            continue
        number, protocol = int(node.get('portid', '0')), node.get('protocol', '')
        if not 1 <= number <= 65535 or protocol not in ('tcp', 'udp', 'sctp'):
            continue
        service = node.find('service')
        attrs = service.attrib if service is not None else {}
        name = attrs.get('name', '')
        if attrs.get('tunnel') == 'ssl':
            name = 'ssl/' + name
        ports.append(dict(port=number, protocol=protocol, service=name,
                          version=' '.join(attrs[k] for k in ('product', 'version', 'extrainfo') if attrs.get(k)),
                          state=state.get('state')))
    scripts = [dict(id=n.get('id', ''), output=n.get('output', '')) for n in host.iter('script')]
    return dict(target=target or (addresses[0] if addresses else 'imported-host'), ports=ports, scripts=scripts)


def merge_findings(ctx, findings):
    keys = {(f['value'], f['source'], f['transform'], f['line']) for f in ctx.flag_evidence}
    for finding in findings:
        key = (finding['value'], finding['source'], finding['transform'], finding['line'])
        if key not in keys:
            keys.add(key)
            ctx.flag_evidence.append(finding)
        pair = (finding['value'], finding['source'])
        if finding['confidence'] != 'low' and pair not in ctx.flags_found:
            ctx.flags_found.append(pair)


def write_json_report(ctx, version):
    """Stable machine-readable evidence; no claim of platform verification."""
    report = dict(schema_version=1, tool_version=version, target=ctx.target,
                  candidate_count=len({f['value'] for f in ctx.flag_evidence}),
                  flags_verified=False, candidates=ctx.flag_evidence,
                  ports=[vars(p) for p in ctx.open_ports],
                  recommendations=list(dict.fromkeys(ctx.recommendations)),
                  quick_wins=list(dict.fromkeys(ctx.quick_wins)), warnings=ctx.analysis_warnings)
    destination = ctx.output_dir / 'REPORT.json'
    temporary = destination.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding='utf-8')
    temporary.replace(destination)
    return destination
