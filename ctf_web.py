"""Small, bounded, same-origin CTF web mapper. No JavaScript or form execution."""
from __future__ import annotations

import base64
from collections import defaultdict
from dataclasses import dataclass, field
import gzip
import hashlib
import heapq
import html
from html.parser import HTMLParser
import io
import json
from pathlib import Path
import re
import ssl
import time
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit
import urllib.error
import urllib.request
import uuid

from ctf_evidence import detect

MAX_BODY = 1024 * 1024
MAX_TRANSFER = 16 * 1024 * 1024
MAX_DISCOVERIES = 2000
MUTATING = re.compile(r'(?:^|[/_.?&=\-])(logout|signout|delete|remove|destroy|reset|reboot|shutdown|unsubscribe|truncate|drop)(?:$|[/_.?&=\-])', re.I)
SEEDS = ('', 'robots.txt', 'sitemap.xml', '.git/HEAD', '.git/config', '.env',
         'flag.txt', 'user.txt', 'root.txt', 'backup.zip', 'config.php.bak', 'admin/', 'login/')


def origin(url):
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in ('http', 'https') or not parsed.hostname or parsed.username is not None:
        raise ValueError('Use an HTTP(S) URL without embedded credentials')
    port = parsed.port or (443 if parsed.scheme.lower() == 'https' else 80)
    if not 1 <= port <= 65535:
        raise ValueError('Invalid web port')
    return parsed.scheme.lower(), parsed.hostname.lower(), port


def canonical_url(value, base=None):
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 32 for c in value) or '\\' in value:
        raise ValueError('Invalid or overlong URL')
    value = html.unescape(value.strip())
    if base:
        value = urljoin(base, value)
    scheme, host, port = origin(value)
    parsed = urlsplit(value)
    host = f'[{host}]' if ':' in host else host
    authority = host if port == (443 if scheme == 'https' else 80) else f'{host}:{port}'
    path = parsed.path or '/'
    return urlunsplit((scheme, authority, path, parsed.query, ''))


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.comments = []
        self.forms = []
        self.base_href = None
        self.active_form = None
        self.in_title = False
        self.title = ''

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'base' and self.base_href is None:
            self.base_href = attrs.get('href')
        if tag == 'title':
            self.in_title = True
        if tag == 'form':
            self.active_form = {'action': attrs.get('action', ''), 'method': attrs.get('method', 'get').upper(), 'fields': []}
            if len(self.forms) < 100:
                self.forms.append(self.active_form)
        if tag in ('input', 'select', 'textarea') and self.active_form and attrs.get('name'):
            if len(self.active_form['fields']) < 100:
                self.active_form['fields'].append({'name': attrs['name'][:100], 'type': attrs.get('type', 'text')[:30]})
        if tag in ('a', 'link', 'script', 'iframe') and len(self.links) < MAX_DISCOVERIES:
            link = attrs.get('href' if tag in ('a', 'link') else 'src')
            if link:
                self.links.append((link, 'script' if tag == 'script' else 'link'))
        if tag == 'meta' and attrs.get('http-equiv', '').lower() == 'refresh':
            match = re.search(r'url\s*=\s*(.+)', attrs.get('content', ''), re.I)
            if match:
                self.links.append((match.group(1).strip(' \"\''), 'meta-refresh'))

    def handle_endtag(self, tag):
        if tag == 'form':
            self.active_form = None
        if tag == 'title':
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title = (self.title + data)[:200]

    def handle_comment(self, data):
        if len(self.comments) < 100:
            self.comments.append(data[:2000])


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class WebResult:
    base_url: str
    pages: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    leads: list[dict] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    requests: int = 0
    bytes_read: int = 0
    complete: bool = True


class WebMapper:
    def __init__(self, base_url, output_dir, max_requests=60, max_depth=3,
                 seconds=120, delay=0.1, prefixes=(), include_hashes=False,
                 opener=None, clock=time.monotonic):
        self.base_url = canonical_url(base_url)
        self.scope = origin(self.base_url)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_requests = max_requests
        self.max_depth = max_depth
        self.seconds = seconds
        self.delay = delay
        self.prefixes, self.include_hashes = prefixes, include_hashes
        self.clock = clock
        self.deadline = None
        self.remaining_seconds = float(seconds)
        self.maps_read = 0
        self.last_request = None
        self.result = WebResult(self.base_url)
        self.seen, self.enqueued, self.finding_keys, self.lead_keys = set(), set(), set(), set()
        self.path_variants = defaultdict(int)
        self.body_sources = {}
        self.soft404 = set()
        self.queue = []
        self.serial = 0
        self.baselined = False
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.opener = opener or urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))

    def warn(self, message):
        if message not in self.result.warnings:
            self.result.warnings.append(message)

    def lead(self, kind, url, detail, priority='medium'):
        key = kind, url, detail
        if key not in self.lead_keys and len(self.result.leads) < MAX_DISCOVERIES:
            self.lead_keys.add(key)
            self.result.leads.append(dict(kind=kind, url=url, detail=detail, priority=priority))

    def _available(self):
        if self.result.requests >= self.max_requests:
            self.warn('Web request limit reached; remaining discoveries were not fetched')
            self.result.complete = False
            return False
        if self.result.bytes_read >= MAX_TRANSFER:
            self.warn('Web byte limit reached; remaining discoveries were not fetched')
            self.result.complete = False
            return False
        if self.clock() >= self.deadline:
            self.warn('Web time budget reached; remaining discoveries were not fetched')
            self.result.complete = False
            return False
        return True

    def _allowed(self, url):
        return origin(url) == self.scope

    def enqueue(self, value, parent, depth, reason='link'):
        try:
            url = canonical_url(value, parent)
        except ValueError:
            return
        if not self._allowed(url):
            self.lead('external-reference', parent, url, 'low')
            return
        if MUTATING.search(unquote(urlsplit(url).path + '?' + urlsplit(url).query)):
            self.lead('skipped-action', url, 'Action-like URL recorded for manual review, not fetched', 'low')
            return
        if depth > self.max_depth:
            self.warn('Web depth limit reached; deeper references were not followed')
            return
        if url in self.enqueued or url in self.seen:
            return
        if len(self.enqueued) >= MAX_DISCOVERIES:
            self.warn('Web discovery limit reached')
            self.result.complete = False
            return
        path = urlsplit(url).path
        # Skip non-source assets; downloaded archives are kept for evidence analysis.
        if re.search(r'\.(?:png|jpg|jpeg|gif|webp|svg|ico|woff2?|ttf|mp[34]|avi|pdf)$', path, re.I):
            return
        if self.path_variants[path] >= 3:
            self.warn('Query-variant limit reached for at least one path')
            return
        self.path_variants[path] += 1
        self.enqueued.add(url)
        priority = 0 if reason in ('source-map', 'script') else 1 if re.search(r'flag|user\.txt|root\.txt|\.txt$|\.map$', path, re.I) else 2
        heapq.heappush(self.queue, (depth, priority, self.serial, url, parent, reason))
        self.serial += 1

    def _fetch(self, requested):
        url = requested
        redirects = []
        for _ in range(6):
            if not self._available():
                return None
            if self.last_request is not None and self.delay:
                wait = self.delay - (self.clock() - self.last_request)
                if wait > 0:
                    time.sleep(min(wait, max(0, self.deadline - self.clock())))
                if not self._available():
                    return None
            self.last_request = self.clock()
            self.result.requests += 1
            request = urllib.request.Request(url, headers={
                'User-Agent': 'CTF-Recon-Assistant/2.2 (authorized lab mapping)',
                'Accept-Encoding': 'identity'})
            try:
                try:
                    response = self.opener.open(request, timeout=max(0.05, min(5, self.deadline - self.clock())))
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    status = response.code
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    if status in (301, 302, 303, 307, 308) and headers.get('location'):
                        try:
                            destination = canonical_url(headers['location'], url)
                        except ValueError:
                            self.warn(f'Invalid redirect from {url}')
                            return None
                        redirects.append({'from': url, 'to': destination, 'status': status})
                        if not self._allowed(destination):
                            self.lead('redirect-host', url, f'Inspect lab redirect manually: {destination}', 'high')
                            return dict(url=url, requested=requested, status=status, headers=headers,
                                        data=b'', redirects=redirects, blocked_redirect=destination, truncated=False)
                        if MUTATING.search(unquote(destination)):
                            self.lead('skipped-action', destination, 'Action-like redirect not followed', 'low')
                            return dict(url=url, requested=requested, status=status, headers=headers,
                                        data=b'', redirects=redirects, blocked_redirect=destination, truncated=False)
                        if destination in [hop['from'] for hop in redirects]:
                            self.warn(f'Redirect loop at {destination}')
                            self.result.complete = False
                            return None
                        url = destination
                        continue
                    room = min(MAX_BODY, MAX_TRANSFER - self.result.bytes_read)
                    chunks, size = [], 0
                    reader = getattr(response, 'read1', response.read)
                    while size <= room and self.clock() < self.deadline:
                        chunk = reader(min(65536, room + 1 - size))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        size += len(chunk)
                    data = b''.join(chunks)
                    self.result.bytes_read += len(data)
                    truncated = len(data) > room or self.clock() >= self.deadline
                    data = data[:room]
                    if headers.get('content-encoding', '').lower() == 'gzip':
                        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                            data = gz.read(min(MAX_BODY, max(0, MAX_TRANSFER - self.result.bytes_read)) + 1)
                        self.result.bytes_read += len(data)
                        truncated = truncated or len(data) > MAX_BODY or self.result.bytes_read > MAX_TRANSFER
                        data = data[:MAX_BODY]
                    if truncated:
                        self.warn(f'Response truncated by size/time limit: {url}')
                        self.result.complete = False
                    return dict(url=url, requested=requested, status=status, headers=headers, data=data,
                                redirects=redirects, blocked_redirect=None, truncated=truncated)
            except (OSError, ValueError, EOFError, urllib.error.URLError) as exc:
                self.warn(f'Fetch failed {url}: {str(exc)[:160]}')
                self.result.complete = False
                return None
        self.warn(f'Redirect limit reached: {requested}')
        self.result.complete = False
        return None

    @staticmethod
    def _text(response):
        charset = re.search(r'charset=[\"\']?([\w.-]+)', response['headers'].get('content-type', ''), re.I)
        try:
            return response['data'].decode(charset.group(1) if charset else 'utf-8', errors='replace')
        except LookupError:
            return response['data'].decode('utf-8', errors='replace')

    @staticmethod
    def _signature(text, url):
        # Normalize only the exact request path/token; no fuzzy similarity claims.
        path = urlsplit(url).path
        text = text.replace(html.escape(path), '<PATH>').replace(path, '<PATH>')
        text = re.sub(r'ctf_probe_[0-9a-f]+', '<PROBE>', text)
        return hashlib.sha256(text.strip().encode()).hexdigest()

    def _scan(self, text, source):
        for finding in detect(text, source, self.prefixes, self.include_hashes):
            key = finding['value'], finding['source'], finding['transform'], finding['line']
            if key not in self.finding_keys:
                self.finding_keys.add(key)
                self.result.findings.append(finding)

    def _source_map(self, text, url, depth):
        if self.maps_read >= 20:
            self.warn('Source-map parsing limit reached')
            return
        self.maps_read += 1
        try:
            mapping = json.loads(text)
        except (ValueError, TypeError):
            return
        if not isinstance(mapping, dict) or mapping.get('version') != 3:
            return
        self.lead('source-map', url, 'Source map disclosed; review embedded original source', 'high')
        sources = mapping.get('sources', [])
        contents = mapping.get('sourcesContent', [])
        if not isinstance(sources, list) or not isinstance(contents, list):
            return
        if len(contents) > 100:
            self.warn(f'Source-map entry limit reached: {url}')
        for index, content in enumerate(contents[:100]):
            if not isinstance(content, str):
                continue
            name = str(sources[index])[:200] if index < len(sources) else str(index)
            source = f'{url} ! source[{index}] {name}'
            self._scan(content[:MAX_BODY], source)
            self._js_links(content[:MAX_BODY], url, depth)

    def _js_links(self, text, url, depth):
        patterns = [r'\bfetch\s*\(\s*[\"\']([^\"\']+)[\"\']\s*\)',
                    r'\baxios\.get\s*\(\s*[\"\']([^\"\']+)[\"\']',
                    r'[\"\'](/(?:api|assets|static|files|backup|hidden|secret)/[^\"\'\s<>]{1,180})[\"\']']
        for pattern in patterns:
            for match in list(re.finditer(pattern, text))[:100]:
                self.lead('js-endpoint', url, match.group(1), 'medium')
                self.enqueue(match.group(1), url, depth + 1, 'js-endpoint')
        for match in list(re.finditer(r'sourceMappingURL\s*=\s*([^\s*]+)', text))[:5]:
            reference = match.group(1).strip()
            if reference.startswith('data:application/json') and ';base64,' in reference:
                try:
                    payload = reference.split(';base64,', 1)[1]
                    if len(payload) <= MAX_BODY:
                        self._source_map(base64.b64decode(payload, validate=True).decode('utf-8'), url + '#inline-map', depth)
                except (ValueError, UnicodeError):
                    self.warn(f'Invalid inline source map: {url}')
            elif not reference.startswith('data:'):
                self.enqueue(reference, url, depth + 1, 'source-map')

    def _inspect(self, response, depth, parent, reason):
        url, data = response['url'], response['data']
        self.seen.add(url)
        text = self._text(response)
        digest = hashlib.sha256(data).hexdigest()
        duplicate = self.body_sources.get(digest) if data else None
        soft = response['status'] == 200 and self._signature(text, url) in self.soft404
        suffix = Path(urlsplit(url).path).suffix.lower()
        if suffix not in ('.txt', '.js', '.json', '.map', '.html', '.css', '.zip', '.gz', '.env'):
            suffix = '.bin' if data.startswith((b'PK\x03\x04', b'\x1f\x8b')) else '.txt'
        filename = hashlib.sha256(url.encode()).hexdigest()[:20] + suffix
        saved = None
        if data:
            (self.output_dir / 'bodies').mkdir(exist_ok=True)
            (self.output_dir / 'bodies' / filename).write_bytes(data)
            saved = 'bodies/' + filename
        page = {k: response[k] for k in ('url', 'requested', 'status', 'redirects', 'blocked_redirect', 'truncated')}
        page.update(depth=depth, parent=parent, discovered_by=reason, bytes=len(data), sha256=digest,
                    content_type=response['headers'].get('content-type', ''), saved=saved,
                    duplicate_of=duplicate, soft_404=soft, title='')
        self.result.pages.append(page)
        # Scan all bodies, including soft-404s, so filtering cannot silently discard a flag.
        self._scan(text, url)
        self._scan('\n'.join(f'{k}: {v}' for k, v in response['headers'].items()), url + ' [headers]')
        if response['status'] in (401, 403):
            self.lead('restricted', url, f'HTTP {response["status"]}: review authentication or access requirements', 'medium')
        if soft:
            self.lead('soft-404', url, 'Matches two nonexistent-page baselines; likely catch-all content', 'low')
            return
        if response['status'] != 200:
            return
        if re.search(r'/(?:\.env|\.git/(?:HEAD|config)|config[^/]*\.(?:bak|old)|[^/]+\.(?:zip|sql|bak))$', urlsplit(url).path, re.I):
            self.lead('exposed-file', url, 'Accessible candidate configuration/backup; inspect the saved response', 'high')
        if data:
            self.body_sources.setdefault(digest, url)
        # Duplicates still need relative links resolved against each distinct document URL.
        is_html = 'html' in page['content_type'] or bool(re.search(r'<(?:html|a\s|script|form|title|!--)', text[:4000], re.I))
        if is_html:
            parser = PageParser()
            parser.feed(text)
            page['title'] = parser.title
            document_base = urljoin(url, parser.base_href) if parser.base_href else url
            for form in parser.forms:
                try:
                    form_url = canonical_url(form['action'], document_base)
                except ValueError:
                    continue
                self.result.forms.append(dict(page=url, action=form_url, method=form['method'], fields=form['fields']))
                self.lead('form', url, f'{form["method"]} {form_url}; fields: ' + ', '.join(f['name'] for f in form['fields']), 'medium')
            for reference, kind in parser.links:
                self.enqueue(reference, document_base, depth + 1, kind)
            for comment in parser.comments:
                if re.search(r'\b(?:todo|debug|backup|secret|password|admin|flag|dev)\b', comment, re.I):
                    self.lead('html-comment', url, comment.strip()[:240], 'medium')
                for match in re.finditer(r'(?:https?://[^\s<>\"\']+|/[\w./?=&%+\-]+)', comment):
                    self.enqueue(match.group(), document_base, depth + 1, 'comment')
        path = urlsplit(url).path.lower()
        if path.endswith('/robots.txt'):
            for reference in re.findall(r'(?im)^\s*(?:allow|disallow|sitemap)\s*:\s*(\S+)', text)[:200]:
                if '*' not in reference and '$' not in reference:
                    self.enqueue(reference, url, depth + 1, 'robots')
        if path.endswith('.xml') or 'xml' in page['content_type']:
            for reference in re.findall(r'<loc>\s*(.*?)\s*</loc>', text, re.I)[:200]:
                self.enqueue(reference, url, depth + 1, 'sitemap')
        if path.endswith('.map'):
            self._source_map(text, url, depth)
        if path.endswith(('.js', '.mjs')) or 'javascript' in page['content_type'] or is_html:
            self._js_links(text, url, depth)

    def run(self, extra_seeds=()):
        # Time spent by other enumerators between calls does not consume this budget.
        self.deadline = self.clock() + self.remaining_seconds
        try:
            if not self.baselined:
                self.baselined = True
                samples = []
                for _ in range(2):
                    probe_url = urljoin(self.base_url, 'ctf_probe_' + uuid.uuid4().hex)
                    response = self._fetch(probe_url)
                    if response and response['status'] == 200 and not response['truncated']:
                        samples.append(self._signature(self._text(response), response['url']))
                if len(samples) == 2 and samples[0] == samples[1]:
                    self.soft404.add(samples[0])
                    self.warn('Catch-all 200 response detected; matching pages are flagged as possible soft-404s')
                # Seed the document at depth zero and the rest as shallow discoveries.
                self.enqueue(self.base_url, self.base_url, 0, 'start')
                for seed in SEEDS[1:]:
                    self.enqueue(seed, self.base_url, 1, 'common-path')
            for seed in extra_seeds:
                self.enqueue(seed, self.base_url, 1, 'directory-enumeration')
            while self.queue and self._available():
                depth, _, _, url, parent, reason = heapq.heappop(self.queue)
                if url in self.seen:
                    continue
                self.seen.add(url)
                response = self._fetch(url)
                if response:
                    self._inspect(response, depth, parent, reason)
        except KeyboardInterrupt:
            self.result.complete = False
            self.warn('Web mapping interrupted; partial results saved')
            raise
        finally:
            self.remaining_seconds = max(0.0, self.deadline - self.clock())
            self.save()
        return self.result

    def save(self):
        destination = self.output_dir / 'crawl.json'
        temporary = destination.with_suffix('.json.tmp')
        temporary.write_text(json.dumps(vars(self.result), indent=2, ensure_ascii=True), encoding='utf-8')
        temporary.replace(destination)
        return destination
