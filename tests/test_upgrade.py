import base64
import gzip
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.request
import urllib.error
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ctf_assistant as app
import ctf_evidence as evidence


class EvidenceTests(unittest.TestCase):
    def test_flags_preserve_case(self):
        found = evidence.detect('HTB{CaseSensitive} THM{training} MYCTF{custom}', prefixes=['MYCTF'])
        self.assertTrue({'HTB{CaseSensitive}', 'THM{training}', 'MYCTF{custom}'} <=
                        {f['value'] for f in found if f['confidence'] == 'high'})

    def test_hash_context(self):
        flag = '0123456789abcdef0123456789abcdef'
        self.assertEqual(evidence.detect(flag, 'checksums.txt'), [])
        self.assertEqual(evidence.detect(flag, '/home/user/user.txt')[0]['confidence'], 'medium')
        self.assertEqual(evidence.detect('flag: ' + flag, 'note.txt')[0]['confidence'], 'medium')
        self.assertEqual(evidence.detect(flag, include_hashes=True)[0]['confidence'], 'low')

    def test_generic_code_is_low_confidence(self):
        findings = evidence.detect('body{color:red}')
        self.assertTrue(findings)
        self.assertTrue(all(f['confidence'] == 'low' for f in findings))

    def test_encoding_layers(self):
        flag = 'THM{layered_evidence}'
        wrapped = base64.b64encode(flag.replace('{', '%7B').replace('}', '%7D').encode()).decode()
        found = evidence.detect(wrapped)
        self.assertTrue(any(f['value'] == flag and f['transform'] == 'raw > base64 > url' for f in found))
        for text in (flag.encode().hex(), 'THM&#123;layered_evidence&#125;', 'GUZ{ynlr­erq_rivqrapr}'.replace('­', '')):
            if text.startswith('GUZ'):
                import codecs
                text = codecs.encode(flag, 'rot_13')
            self.assertTrue(any(f['value'] == flag for f in evidence.detect(text)))

    def test_archives_utf16_and_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with zipfile.ZipFile(root / 'challenge.zip', 'w') as archive:
                archive.writestr('../../escape.txt', b'HTB{zip_member}')
                archive.writestr('wide.txt', 'THM{utf16}'.encode('utf-16'))
                archive.writestr('inner.gz', gzip.compress(b'flag{nested}'))
            found = evidence.ArtifactScanner().scan([root])
            self.assertTrue({'HTB{zip_member}', 'THM{utf16}', 'flag{nested}'} <= {f['value'] for f in found})
            self.assertEqual(list(root.iterdir()), [root / 'challenge.zip'])

    def test_limits_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'large.txt').write_bytes(b'x' * (evidence.MAX_FILE + 1))
            (root / 'SUMMARY.txt').write_text('HTB{should_ignore}')
            (root / 'link').symlink_to(root / 'SUMMARY.txt')
            scanner = evidence.ArtifactScanner()
            self.assertEqual(scanner.scan([root]), [])
            self.assertTrue(scanner.warnings)
            (root / 'bomb.gz').write_bytes(gzip.compress(b'x' * (evidence.MAX_FILE + 1)))
            scanner.scan([root / 'bomb.gz'])
            self.assertTrue(any('limit' in warning for warning in scanner.warnings))

    def test_dedup_and_json(self):
        with tempfile.TemporaryDirectory() as temp:
            ctx = app.ScanContext('offline', Path(temp))
            app.record_flags(ctx, 'THM{one}', 'notes.txt')
            app.record_flags(ctx, 'THM{one}', 'notes.txt')
            self.assertEqual(len(ctx.flags_found), 1)
            evidence.write_json_report(ctx, 'test')
            report = json.loads((Path(temp) / 'REPORT.json').read_text())
            self.assertFalse(report['flags_verified'])
            self.assertEqual(report['candidates'][0]['source'], 'notes.txt')


XML = '''<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host><address addr="10.10.10.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="53"><state state="open"/><service name="domain"/></port>
<port protocol="udp" portid="53"><state state="open|filtered"/><service name="domain"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="http" tunnel="ssl" product="nginx" version="1.0"/><script id="http-title" output="HTB{nse_evidence}"/></port>
<port protocol="tcp" portid="22"><state state="closed"/></port></ports></host></nmaprun>'''


class IntegrationTests(unittest.TestCase):
    def test_xml_and_offline_cli_never_calls_network(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'scan.xml').write_text(XML)
            (root / 'evidence.txt').write_text('THM{offline}')
            parsed = evidence.parse_nmap(root / 'scan.xml')
            self.assertEqual(len(parsed['ports']), 3)
            self.assertEqual(parsed['ports'][1]['state'], 'open|filtered')
            self.assertEqual(parsed['ports'][2]['service'], 'ssl/http')
            argv = ['ctf_assistant.py', '--import-nmap', str(root / 'scan.xml'), '--analyze',
                    str(root / 'evidence.txt'), '-o', str(root / 'report')]
            with patch.object(sys, 'argv', argv), patch('socket.gethostbyname', side_effect=AssertionError('DNS')), \
                 patch('subprocess.run', side_effect=AssertionError('subprocess')), \
                 patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('HTTP')):
                self.assertEqual(app.main(), 0)
            report = json.loads((root / 'report/REPORT.json').read_text())
            self.assertTrue({'THM{offline}', 'HTB{nse_evidence}'} <= {f['value'] for f in report['candidates']})

    def test_xml_rejects_entities_and_ambiguous_hosts(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'scan.xml'
            path.write_text(XML.replace('</nmaprun>', '<host/></nmaprun>'))
            with self.assertRaises(ValueError):
                evidence.parse_nmap(path)
            self.assertEqual(evidence.parse_nmap(path, '10.10.10.10')['target'], '10.10.10.10')
            path.write_text('<!DOCTYPE x [<!ENTITY test "a">]><nmaprun/>')
            with self.assertRaises(ValueError):
                evidence.parse_nmap(path)

    def test_timeout_preserves_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            error = subprocess.TimeoutExpired(['test'], 1, output=b'THM{partial}\xff')
            with patch('subprocess.run', side_effect=error):
                rc, output = app.run_command(['test'], Path(temp) / 'out.txt', timeout=1)
            self.assertEqual(rc, 124)
            self.assertIn('THM{partial}', output)

    def test_tcp_udp_collision(self):
        ctx = app.ScanContext('test', Path('.'), open_ports=[app.OpenPort(53, 'udp', 'domain')])
        app._apply_deep_scan_output(ctx, '53/tcp open domain Test DNS')
        self.assertEqual(len(ctx.open_ports), 2)
        self.assertEqual(ctx.open_ports[0].version, '')

    def test_http_discovery_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            ctx = app.ScanContext('test', Path(temp))
            with patch.object(app, 'safe_fetch', return_value=(200, 'HTB{same_origin}')) as fetch:
                app.auto_fetch_and_scan(ctx, 'http://lab.test/',
                                        ['http://external.test/x', '//external.test/x', '/flag.txt'], Path(temp))
                fetch.assert_called_once_with('http://lab.test/flag.txt')
            self.assertEqual(len(ctx.analysis_warnings), 2)

    def test_cross_origin_redirect_rejected(self):
        handler = app.SameOriginRedirect()
        request = urllib.request.Request('http://lab.test/start')
        with self.assertRaises(urllib.error.HTTPError):
            handler.redirect_request(request, None, 302, 'redirect', {}, 'http://external.test/')

    def test_bad_ports_fail_before_network(self):
        for ports in ('0', '65536', '22,,80', 'bad'):
            with patch.object(sys, 'argv', ['ctf_assistant.py', '-p', ports]), \
                 patch('socket.gethostbyname', side_effect=AssertionError('DNS')):
                with self.assertRaises(SystemExit) as exc:
                    app.main()
                self.assertEqual(exc.exception.code, 2)

    def test_resume_mismatched_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'session.json').write_text(json.dumps({'target': '10.0.0.2'}))
            with patch.object(sys, 'argv', ['ctf_assistant.py', '-t', '10.0.0.1', '--resume', temp]), \
                 patch.object(app, 'check_tools', side_effect=AssertionError('must fail early')):
                self.assertEqual(app.main(), 2)

    def test_mocked_live_workflow_and_resume(self):
        with tempfile.TemporaryDirectory() as temp:
            def deep(ctx, ports):
                directory = ctx.output_dir / 'nmap'
                directory.mkdir(parents=True, exist_ok=True)
                (directory / 'deep_scan.nmap').write_text('80/tcp open http Test Server')
                app.mark_done(directory / 'deep_scan.done')
                app._apply_deep_scan_output(ctx, '80/tcp open http Test Server')
            def enumeration(ctx, *args, **kwargs):
                (ctx.output_dir / 'user.txt').write_text('0123456789abcdef0123456789abcdef')
            argv = ['ctf_assistant.py', '-t', '10.10.10.10', '-p', '80']
            with patch.object(app, 'check_tools', return_value={}), \
                 patch.object(app, 'print_tool_checklist'), \
                 patch.object(app, 'phase_deep_scan', side_effect=deep) as deep_mock, \
                 patch.object(app, 'phase_service_enum', side_effect=enumeration), \
                 patch.object(app, 'searchsploit_lookup'), \
                 patch.object(sys, 'argv', argv + ['-o', temp]):
                self.assertEqual(app.main(), 0)
                with patch.object(sys, 'argv', argv + ['--resume', temp]):
                    self.assertEqual(app.main(), 0)
                self.assertEqual(deep_mock.call_count, 1)
            report = json.loads((Path(temp) / 'REPORT.json').read_text())
            self.assertTrue(any(f['kind'] == 'hex32' for f in report['candidates']))

    def test_ftp_enforces_size_without_size_command(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as temp:
            ftp = Mock()
            ftp.mlsd.return_value = [('too-large.txt', {'type': 'file'})]
            ftp.size.side_effect = OSError('SIZE unavailable')
            ftp.retrbinary.side_effect = lambda command, callback: callback(b'x' * (app.MAX_LOOT_FILE_BYTES + 1))
            self.assertEqual(app._ftp_walk(ftp, '', Path(temp), app.ScanContext('test', Path(temp))), 0)
            self.assertFalse((Path(temp) / 'too-large.txt').exists())

    def test_missing_resume_logs_are_rerun(self):
        with tempfile.TemporaryDirectory() as temp:
            ctx = app.ScanContext('test', Path(temp))
            app.mark_done(Path(temp) / 'nmap/quick_scan.done')
            app.mark_done(Path(temp) / 'nmap/deep_scan.done')
            self.assertIsNone(app.resume_load_quick_scan(ctx))
            self.assertFalse(app.resume_load_deep_scan(ctx))

    def test_ftp_path_escape(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as temp:
            ftp = Mock()
            ftp.mlsd.return_value = [('../outside', {'type': 'file'})]
            ctx = app.ScanContext('test', Path(temp))
            self.assertEqual(app._ftp_walk(ftp, '', Path(temp), ctx), 0)
            ftp.retrbinary.assert_not_called()


if __name__ == '__main__':
    unittest.main()
