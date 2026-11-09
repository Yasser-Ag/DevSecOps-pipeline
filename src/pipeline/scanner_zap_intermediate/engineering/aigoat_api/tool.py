"""Execute one retained tool against only the supplied bounded API inputs."""
import argparse
import json
import os
from pathlib import Path
import subprocess
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tool', choices=['nuclei', 'schemathesis', 'zap'], required=True)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--base', required=True)
    args = parser.parse_args()
    token = json.loads((args.input / 'authorization.json').read_text())['token']
    header = 'Authorization: Bearer ' + token
    if args.tool == 'nuclei':
        argv = ['/usr/local/bin/nuclei', '-l', str(args.input / 'urls.txt'), '-t', str(args.input / 'template.yaml'),
                '-config', str(args.input / 'nuclei.yml'), '-H', header, '-jsonl', '-o', str(args.input / 'nuclei.jsonl'),
                '-tlog', str(args.input / 'requests.jsonl'), '-elog', str(args.input / 'errors.jsonl'),
                '-duc', '-ni', '-silent', '-no-stdin', '-rl', '2', '-c', '1', '-dr', '-retries', '0', '-timeout', '10']
    elif args.tool == 'schemathesis':
        argv = ['<LAB_ROOT>/environment/toolset-completion-20260922-01/python/bin/schemathesis',
                'run', str(args.input / 'openapi.json'), '--url', args.base, '--header', header,
                '--workers', '1', '--phases', 'examples,fuzzing', '--mode', 'positive', '--max-examples', '5',
                '--seed', '117', '--no-shrink', '--request-timeout', '15', '--request-retries', '0',
                '--generation-database', 'none', '--checks', 'not_a_server_error',
                '--report', 'json,junit,har', '--report-dir', str(args.input / 'reports')]
    else:
        os.environ.update(ZAP_AUTH_HEADER='Authorization', ZAP_AUTH_HEADER_VALUE='Bearer ' + token,
                          ZAP_AUTH_HEADER_SITE=urlsplit(args.base).hostname)
        argv = ['/zap/zap-api-scan.py', '-t', str(args.input / 'openapi.json'), '-f', 'openapi',
                '-S', '-J', 'zap.json', '-P', '10091', '-T', '3',
                '-z', '-silent -notel -config connection.timeoutInSecs=15']
    result = subprocess.run(argv, cwd=args.input)
    if args.tool == 'zap':
        counters = {}
        for name in ('cpu.stat', 'memory.peak', 'memory.events'):
            path = Path('/sys/fs/cgroup') / name
            counters[name] = path.read_text() if path.exists() else None
        (args.input / 'container_accounting.json').write_text(json.dumps({
            'scope': 'Scanner container cgroup just before wrapper exit; includes Java children.',
            'counters': counters}, indent=2) + '\n')
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
