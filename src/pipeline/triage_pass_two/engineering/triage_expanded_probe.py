import json
import os
from pathlib import Path
import urllib.error
import urllib.request

def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

def validate_accounting(response, expected_prompt, output_limit):
    usage = response['usage']; timings = response['timings']
    if usage['prompt_tokens'] != expected_prompt or timings['prompt_n'] != expected_prompt:
        raise ValueError('Prompt accounting differs from qualified input')
    if usage['prompt_tokens_details']['cached_tokens'] != 0 or timings['cache_n'] != 0:
        raise ValueError('Prompt reuse detected')
    generated = usage['completion_tokens']
    if generated != timings['predicted_n'] or not 0 <= generated <= output_limit:
        raise ValueError('Output accounting differs')
    if usage['total_tokens'] != expected_prompt + generated:
        raise ValueError('Total token accounting differs')
    if expected_prompt + generated > 4096:
        raise ValueError('Context limit exceeded')
    return {'prompt_tokens': expected_prompt, 'completion_tokens': generated,
            'cached_tokens': 0, 'prompt_ms': timings['prompt_ms'],
            'predicted_ms': timings['predicted_ms']}

def server_resources(pid):
    fields = Path('/proc/' + str(pid) + '/stat').read_text().rsplit(')', 1)[1].split()
    ticks = os.sysconf('SC_CLK_TCK')
    status = dict(line.split(':', 1) for line in Path('/proc/' + str(pid) + '/status').read_text().splitlines())
    return {'user_cpu_seconds': int(fields[11]) / ticks,
            'system_cpu_seconds': int(fields[12]) / ticks,
            'rss_kib': int(status['VmRSS'].split()[0]),
            'high_water_rss_kib': int(status['VmHWM'].split()[0])}

def post(route, payload, raw_path=None):
    request = urllib.request.Request('http://127.0.0.1:10080' + route,
        data=json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode(),
        headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            raw = response.read()
    except urllib.error.HTTPError as error:
        if raw_path is not None:
            raw_path.write_bytes(error.read())
        raise
    if raw_path is not None:
        raw_path.write_bytes(raw)
    return json.loads(raw)
