"""Evidence-driven next steps. Suggestions are not vulnerability confirmations."""
from pathlib import Path


def cell(value):
    return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('|', '&#124;').replace('`', '&#96;').replace('\n', ' ').replace('\r', ' ')


def prioritize(ctx):
    steps, keys = [], set()

    def add(priority, category, title, evidence, action):
        key = category, evidence
        if key not in keys:
            keys.add(key)
            steps.append(dict(priority=priority, category=category, title=title, evidence=evidence, action=action))

    flags = {}
    for finding in ctx.flag_evidence:
        if finding['confidence'] != 'low':
            flags.setdefault(finding['value'], finding)
    for value, finding in flags.items():
        add(1, 'flag-candidate', 'Verify a flag candidate', finding['source'],
            f"Compare {value} with the event format, then submit manually if it belongs to this challenge.")
    actions = {
        'source-map': (2, 'Read original source exposed by the source map; identify hidden routes and challenge logic.'),
        'exposed-file': (2, 'Inspect the saved file; analyze downloaded archives offline. A 200 response alone is not proof of exposure.'),
        'redirect-host': (2, 'Check this hostname against the challenge scope. Configure the lab hostname if appropriate and run --web-url explicitly.'),
        'html-comment': (3, 'Inspect this source comment and correlate any mentioned files or routes.'),
        'js-endpoint': (3, 'Review this endpoint and its saved response. Parameters may require manual investigation.'),
        'form': (3, 'Inspect form fields and application behavior manually; the mapper does not submit forms.'),
        'restricted': (4, 'Check the challenge instructions for credentials and authentication requirements.'),
    }
    for web in ctx.web_results:
        for lead in web.get('leads', []):
            if lead['kind'] in actions:
                priority, action = actions[lead['kind']]
                add(priority, lead['kind'], lead['detail'], lead['url'], action)
        if not web.get('complete', True):
            add(2, 'incomplete-web', 'Web discovery was incomplete', web['base_url'],
                'Read crawl warnings. Increase the relevant --web-pages/--web-seconds limit or resolve fetch errors before retrying.')
    for port in ctx.open_ports:
        identity = f'{port.port}/{port.protocol} {port.service}'
        if port.state != 'open':
            add(4, 'uncertain-port', 'Port state is not confirmed open', identity,
                'Confirm the service before treating it as an available attack surface.')
        elif not port.service or port.service.rstrip('?') in ('unknown', 'tcpwrapped') or port.service.endswith('?'):
            add(3, 'unknown-service', 'Service identity needs confirmation', identity,
                'Review the Nmap banner and verify the protocol before choosing an enumeration tool.')
    if not steps:
        add(5, 'manual-review', 'No prioritized evidence yet', ctx.target,
            'Read the scan logs and challenge description. Check VPN connectivity and consider a full port scan if you used --fast.')
    return sorted(steps, key=lambda step: (step['priority'], step['category'], step['evidence']))


def write_triage(ctx):
    ctx.next_steps = prioritize(ctx)
    lines = ['# Prioritized next steps', '',
             'Ordered by observed evidence. These are leads, not confirmed vulnerabilities or verified flags.', '']
    for index, step in enumerate(ctx.next_steps, 1):
        lines.extend([f'## {index}. P{step["priority"]}: {cell(step["title"])}', '',
                      f'Evidence: {cell(step["evidence"])}', '', cell(step['action']), ''])
    destination = ctx.output_dir / 'NEXT_STEPS.md'
    destination.write_text('\n'.join(lines), encoding='utf-8')
    lines = ['# Web discovery map', '', 'Only GET requests are sent. Forms are inventoried, not submitted.', '']
    for web in ctx.web_results:
        lines.extend([f'## {cell(web["base_url"])}', '',
                      f'Requests: {web["requests"]}; bytes counted: {web["bytes_read"]}; completed within configured traversal: {web["complete"]}.', '',
                      '| Status | URL | Discovery | Notes |', '|---|---|---|---|'])
        for page in web.get('pages', []):
            notes = []
            if page.get('soft_404'):
                notes.append('possible soft-404')
            if page.get('duplicate_of'):
                notes.append('same body as ' + page['duplicate_of'])
            if page.get('blocked_redirect'):
                notes.append('redirect not followed: ' + page['blocked_redirect'])
            if page.get('truncated'):
                notes.append('truncated')
            lines.append('| ' + ' | '.join(cell(item) for item in (page['status'], page['url'], page['discovered_by'], '; '.join(notes))) + ' |')
        if web.get('forms'):
            lines.extend(['', '### Forms (manual review)', ''])
            for form in web['forms']:
                lines.append('- ' + cell(f"{form['method']} {form['action']} — fields: " + ', '.join(field['name'] for field in form['fields'])))
        lines.extend(['', '### Warnings', ''] + ['- ' + cell(warning) for warning in web.get('warnings', [])] + [''])
    if not ctx.web_results:
        lines.append('No web mapping results. Use a live scan or --web-url for web discovery.')
    (ctx.output_dir / 'WEB_MAP.md').write_text('\n'.join(lines), encoding='utf-8')
    return destination
