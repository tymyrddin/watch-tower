#!/usr/bin/env python3
"""
Firmware vulnerability findings ingestion script.

Normalises lab output and posts it to the Shuffle webhook.

Usage:
    python3 ingestion/ingest_findings.py examples/findings.json
    python3 ingestion/ingest_findings.py my_findings.json

Accepts two input formats:
  - Canonical:   {"research_batch": {...}, "firmware": [...]}
  - Simplified:  {"firmwares": [...]}  (quick lab output)

See docs/schema.md for the full field reference.
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)


def load_env():
    """Load .env into os.environ. Values already set in the environment take priority."""
    env_file = os.path.join(REPO_ROOT, '.env')
    if not os.path.exists(env_file):
        return
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, _, val = line.partition('=')
            val = val.strip().strip('"').strip("'")
            os.environ.setdefault(key.strip(), val)


def webhook_url():
    for name in ('.shuffle-import-webhook-id', '.shuffle-webhook-id'):
        wf = os.path.join(REPO_ROOT, name)
        if os.path.exists(wf):
            wid = open(wf).read().strip()
            base = os.environ.get('SHUFFLE_URL', 'http://localhost:5001')
            return f'{base}/api/v1/hooks/webhook_{wid}'
    sys.exit(
        'ERROR: .shuffle-import-webhook-id not found.\n'
        'Run:   bash scripts/init-lab.sh'
    )


def normalise(raw):
    """Return data in canonical format regardless of input shape."""

    # Canonical schema
    if 'firmware' in raw and isinstance(raw['firmware'], list):
        return raw

    # Simplified format: {"firmwares": [...]}
    if 'firmwares' in raw:
        firmware = []
        for fw in raw['firmwares']:
            vulns = []
            for i, v in enumerate(fw.get('vulnerabilities', [])):
                if 'cve' in v:
                    vulns.append({'research_id': v['cve'], 'cve': v['cve']})
                elif 'finding' in v:
                    vulns.append({
                        'research_id': f'FINDING-{i + 1:03d}',
                        'cve': None,
                        'title': v['finding'],
                    })
            firmware.append({
                'vendor':          fw.get('vendor', 'Unknown'),
                'product':         fw.get('device', fw.get('product', 'Unknown')),
                'version':         fw.get('version', ''),
                'vulnerabilities': vulns,
            })
        return {'research_batch': raw.get('research_batch', {}), 'firmware': firmware}

    print('ERROR: unrecognised input format. See docs/schema.md', file=sys.stderr)
    sys.exit(1)


def validate(data):
    errors = []
    for fw in data.get('firmware', []):
        if not fw.get('vendor') or not fw.get('product'):
            errors.append(f'firmware entry missing vendor or product: {fw}')
        for v in fw.get('vulnerabilities', []):
            cve = v.get('cve')
            if cve and not _CVE_RE.match(cve):
                errors.append(f'invalid CVE format: {cve!r}')
    if errors:
        for e in errors:
            print(f'VALIDATION ERROR: {e}', file=sys.stderr)
        sys.exit(1)


def post(url, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        sys.exit(f'ERROR: webhook returned HTTP {e.code}: {e.read().decode()[:200]}')
    except Exception as e:
        sys.exit(f'ERROR posting to Shuffle: {e}')


def main():
    if len(sys.argv) != 2:
        sys.exit('Usage: bash scripts/import.sh --file <findings.json>')

    load_env()

    findings_file = sys.argv[1]
    if not os.path.exists(findings_file):
        sys.exit(f'ERROR: file not found: {findings_file}')

    with open(findings_file) as f:
        try:
            raw = json.load(f)
        except json.JSONDecodeError as e:
            sys.exit(f'ERROR: invalid JSON in {findings_file}: {e}')

    data = normalise(raw)
    validate(data)

    url = webhook_url()
    fw_count   = len(data.get('firmware', []))
    vuln_count = sum(len(fw.get('vulnerabilities', [])) for fw in data.get('firmware', []))

    print(f'[*] {fw_count} firmware image(s), {vuln_count} finding(s)')
    print('[*] Posting to Shuffle...')

    result = post(url, data)

    if result.get('success'):
        print('[+] Accepted — pipeline running.')
        print()
        print('    MISP events:   http://localhost:8080')
        print('    Workflow runs: http://localhost:3001')
        print()
        print('    Results appear in MISP within ~30 seconds.')
    else:
        print(f'[-] Unexpected response: {result}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
