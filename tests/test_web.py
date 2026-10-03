"""Local HTTP fixture; no external targets or competition infrastructure."""
import base64
from contextlib import contextmanager
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ctf_web import WebMapper, canonical_url
import ctf_assistant as app


@contextmanager
def challenge_server(routes, fallback=None):
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(('GET', self.path))
            result = routes.get(self.path)
            if result is None:
                result = fallback(self.path) if fallback else (404, {}, b'missing')
            status, headers, data = result
            if isinstance(data, str):
                data = data.encode()
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass
        def do_POST(self):
            requests.append(('POST', self.path))
            self.send_response(405)
            self.end_headers()
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}/', requests
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def mapper(url, directory, **kwargs):
    return WebMapper(url, directory, delay=0, **kwargs)


class WebTests(unittest.TestCase):
    def test_html_robots_js_sourcemap_and_headers(self):
        source_map = json.dumps({'version': 3, 'sources': ['src/secret.js'],
                                 'sourcesContent': ['const hidden = "HTB{source_map_flag}"; fetch("/api/flag")']})
        routes = {
            '/': (200, {'Content-Type': 'text/html'}, '''<title>Practice Box</title><script src="/app.js"></script>
                  <!-- TODO inspect /hidden/note.txt -->
                  <form method="post" action="/login"><input name="username"><input type="password" name="password"></form>
                  <a href="/logout">logout</a>'''),
            '/robots.txt': (200, {}, 'Disallow: /hidden/robots.txt'),
            '/hidden/robots.txt': (200, {}, 'THM{robots_found}'),
            '/hidden/note.txt': (200, {}, 'THM{comment_found}'),
            '/app.js': (200, {'Content-Type': 'application/javascript'}, 'fetch("/api/info"); //# sourceMappingURL=app.js.map'),
            '/app.js.map': (200, {'Content-Type': 'application/json'}, source_map),
            '/api/info': (200, {'X-CTF-Hint': 'flag{header_found}'}, '{"status":"ok"}'),
            '/api/flag': (200, {}, 'THM{endpoint_found}'),
        }
        with tempfile.TemporaryDirectory() as temp, challenge_server(routes) as (url, requests):
            result = mapper(url, temp).run()
            values = {f['value'] for f in result.findings}
            self.assertTrue({'HTB{source_map_flag}', 'THM{robots_found}', 'THM{comment_found}',
                             'flag{header_found}', 'THM{endpoint_found}'} <= values)
            self.assertTrue(any('source[0] src/secret.js' in f['source'] for f in result.findings))
            self.assertEqual(result.forms[0]['method'], 'POST')
            self.assertEqual(result.forms[0]['fields'][1]['name'], 'password')
            self.assertNotIn(('GET', '/logout'), requests)
            self.assertFalse(any(method == 'POST' for method, path in requests))
            self.assertTrue((Path(temp) / 'crawl.json').exists())

    def test_cross_origin_references_and_redirects_not_fetched(self):
        with challenge_server({'/steal': (200, {}, 'HTB{external}')}) as (external, external_requests):
            routes = {'/': (200, {'Content-Type': 'text/html'}, f'<a href="{external}steal">external</a><a href="/go">go</a>'),
                      '/go': (302, {'Location': external + 'steal'}, '')}
            with tempfile.TemporaryDirectory() as temp, challenge_server(routes) as (url, _):
                result = mapper(url, temp).run()
                self.assertEqual(external_requests, [])
                self.assertTrue(any(lead['kind'] == 'redirect-host' for lead in result.leads))

    def test_soft404_retains_candidates(self):
        def catchall(path):
            return 200, {'Content-Type': 'text/html'}, f'<html>Missing {path} HTB{{catchall_candidate}}</html>'
        with tempfile.TemporaryDirectory() as temp, challenge_server({}, catchall) as (url, _):
            result = mapper(url, temp).run()
            self.assertTrue(any(page['soft_404'] for page in result.pages))
            self.assertFalse(any(lead['kind'] == 'exposed-file' for lead in result.leads))
            self.assertTrue(any(f['value'] == 'HTB{catchall_candidate}' for f in result.findings))

    def test_request_budget_includes_baselines_and_redirects(self):
        routes = {'/': (302, {'Location': '/landing'}, ''), '/landing': (200, {}, 'home')}
        with tempfile.TemporaryDirectory() as temp, challenge_server(routes) as (url, requests):
            result = mapper(url, temp, max_requests=4).run()
            self.assertEqual(result.requests, 4)
            self.assertEqual(len(requests), 4)
            self.assertFalse(result.complete)
            self.assertTrue(any('request limit' in w for w in result.warnings))

    def test_depth_bound(self):
        routes = {'/': (200, {'Content-Type': 'text/html'}, '<a href="/first">first</a>'),
                  '/first': (200, {'Content-Type': 'text/html'}, '<a href="/deep">deep</a>'),
                  '/deep': (200, {}, 'THM{too_deep}')}
        with tempfile.TemporaryDirectory() as temp, challenge_server(routes) as (url, requests):
            mapper(url, temp, max_depth=1).run()
            self.assertNotIn(('GET', '/deep'), requests)

    def test_inline_source_map_and_sitemap(self):
        mapping = base64.b64encode(json.dumps({'version': 3, 'sources': ['a.ts'], 'sourcesContent': ['THM{inline_map}']}).encode()).decode()
        routes = {'/': (200, {'Content-Type': 'text/html'}, '<script src="/app.js"></script>'),
                  '/app.js': (200, {}, '//# sourceMappingURL=data:application/json;base64,' + mapping),
                  '/sitemap.xml': (200, {'Content-Type': 'application/xml'}, '<urlset><url><loc>/hidden.txt</loc></url></urlset>'),
                  '/hidden.txt': (200, {}, 'flag{sitemap}')}
        with tempfile.TemporaryDirectory() as temp, challenge_server(routes) as (url, _):
            result = mapper(url, temp).run()
            self.assertTrue({'THM{inline_map}', 'flag{sitemap}'} <= {f['value'] for f in result.findings})

    def test_redirect_loop_bounded(self):
        routes = {'/': (302, {'Location': '/loop'}, ''), '/loop': (302, {'Location': '/'}, '')}
        with tempfile.TemporaryDirectory() as temp, challenge_server(routes) as (url, requests):
            result = mapper(url, temp, max_requests=30).run()
            self.assertTrue(any('Redirect loop' in warning for warning in result.warnings))
            self.assertLessEqual(len(requests), 30)

    def test_cli_and_triage(self):
        routes = {'/': (200, {'Content-Type': 'text/html'}, '<!-- flag{cli_result} --><script src="/app.js"></script>'),
                  '/app.js': (200, {}, '//# sourceMappingURL=app.js.map'),
                  '/app.js.map': (200, {}, '{"version":3,"sources":[],"sourcesContent":[]}')}
        with tempfile.TemporaryDirectory() as temp, challenge_server(routes) as (url, requests):
            output = Path(temp) / 'results'
            args = ['ctf_assistant.py', '--web-url', url, '--web-delay', '0', '-o', str(output)]
            with patch.object(sys, 'argv', args), patch('subprocess.run', side_effect=AssertionError('No external commands')):
                self.assertEqual(app.main(), 0)
            report = json.loads((output / 'REPORT.json').read_text())
            self.assertEqual(report['schema_version'], 2)
            self.assertEqual(report['next_steps'][0]['category'], 'flag-candidate')
            self.assertTrue((output / 'WEB_MAP.md').exists())
            self.assertTrue((output / 'NEXT_STEPS.md').exists())
            self.assertTrue(report['web'])

    def test_repeated_run_keeps_budget_without_counting_other_tools(self):
        clock = [100.0]
        routes = {'/': (200, {}, 'home'), '/later.txt': (200, {}, 'THM{later_discovery}')}
        with tempfile.TemporaryDirectory() as temp, challenge_server(routes) as (url, requests):
            crawler = mapper(url, temp, seconds=10, clock=lambda: clock[0])
            crawler.run()
            initial_requests = crawler.result.requests
            clock[0] += 300  # A separate tool runs; crawler did not spend this time.
            result = crawler.run(['/later.txt'])
            self.assertEqual(result.requests, initial_requests + 1)
            self.assertTrue(any(f['value'] == 'THM{later_discovery}' for f in result.findings))

    def test_expired_time_budget_makes_no_request(self):
        with tempfile.TemporaryDirectory() as temp:
            crawler = mapper('http://127.0.0.1:1/', temp)
            crawler.remaining_seconds = 0
            with patch.object(crawler.opener, 'open', side_effect=AssertionError('No request after deadline')):
                result = crawler.run()
            self.assertEqual(result.requests, 0)
            self.assertFalse(result.complete)
            self.assertTrue(any('time budget' in warning for warning in result.warnings))

    def test_ip_http_phase_uses_mapper_automatically(self):
        from urllib.parse import urlsplit
        routes = {'/': (200, {'Content-Type': 'text/html'}, '<script src="/app.js"></script>'),
                  '/app.js': (200, {}, 'const clue="HTB{ip_workflow}"')}
        with tempfile.TemporaryDirectory() as temp, challenge_server(routes) as (url, requests):
            ctx = app.ScanContext('127.0.0.1', Path(temp), web_delay=0)
            port = app.OpenPort(urlsplit(url).port, service='http')
            with patch.object(app, 'find_wordlist', return_value=None):
                self.assertTrue(app.phase_http_enum(ctx, port, {}, False))
            self.assertTrue(any(flag == 'HTB{ip_workflow}' for flag, source in ctx.flags_found))
            self.assertEqual(len(ctx.web_results), 1)
            self.assertTrue((Path(temp) / 'http' / f'http_{port.port}.done').exists())

    def test_url_canonicalization(self):
        self.assertEqual(canonical_url('HTTP://LAB.TEST:80/a#fragment'), 'http://lab.test/a')
        self.assertEqual(canonical_url('/a', 'http://lab.test/b'), 'http://lab.test/a')
        for value in ('file:///etc/passwd', 'http://user:pass@lab.test/', 'http://lab.test:99999', 'http://lab.test/\nheader'):
            with self.assertRaises(ValueError):
                canonical_url(value)

    def test_body_size_limit(self):
        routes = {'/': (200, {}, b'x' * (1024 * 1024 + 100))}
        with tempfile.TemporaryDirectory() as temp, challenge_server(routes) as (url, _):
            result = mapper(url, temp).run()
            page = next(page for page in result.pages if page['url'] == url)
            self.assertTrue(page['truncated'])
            self.assertEqual(page['bytes'], 1024 * 1024)
            self.assertFalse(result.complete)

    def test_duplicate_body_still_resolves_relative_links(self):
        common = '<a href="note.txt">note</a>'
        routes = {'/': (200, {'Content-Type': 'text/html'}, '<a href="/a/">a</a><a href="/b/">b</a>'),
                  '/a/': (200, {'Content-Type': 'text/html'}, common), '/b/': (200, {'Content-Type': 'text/html'}, common),
                  '/a/note.txt': (200, {}, 'THM{a_note}'), '/b/note.txt': (200, {}, 'THM{b_note}')}
        with tempfile.TemporaryDirectory() as temp, challenge_server(routes) as (url, _):
            result = mapper(url, temp).run()
            self.assertTrue({'THM{a_note}', 'THM{b_note}'} <= {f['value'] for f in result.findings})


if __name__ == '__main__':
    unittest.main()
