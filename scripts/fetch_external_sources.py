#!/usr/bin/env python3
"""Retrieve pinned third-party source and restore licensed excerpts locally.

Nothing is sent to a model or scanner. A source is accepted only if its full-file
SHA-256 agrees with the published descriptor. Restored files retain the upstream
license and are not part of the Apache-2.0/CC-BY-4.0 redistribution.
"""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def fetch_bytes(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'research-source-reconstruction/1.0'})
    with urllib.request.urlopen(request, timeout=45) as response:
        return response.read()


def heritage_source(descriptor):
    """Try the archived revision, without claiming in advance that it exists."""
    api = 'https://archive.softwareheritage.org/api/1/'
    revision = json.loads(fetch_bytes(api + 'revision/' + descriptor['revision'] + '/'))
    path = urllib.parse.quote(descriptor['path'], safe='/')
    entry = json.loads(fetch_bytes(api + 'revision/' + descriptor['revision'] + '/directory/' + path + '/'))
    if entry.get('type') != 'file':
        raise ValueError('Archived entry is not a file')
    content = entry['content']
    if content['checksums']['sha256'] != descriptor['source_sha256']:
        raise ValueError('Archived source identity differs')
    return fetch_bytes(content['data_url'])


def source_bytes(descriptor, cache, offline=False):
    cached = cache / descriptor['source_sha256']
    if cached.is_file():
        data = cached.read_bytes()
    elif offline:
        raise ValueError('Verified source cache is incomplete: ' + descriptor['path'])
    else:
        repo = descriptor['repository'].removeprefix('https://github.com/').removesuffix('.git')
        url = 'https://raw.githubusercontent.com/' + repo + '/' + descriptor['revision'] + '/' + descriptor['path']
        try:
            data = fetch_bytes(url)
        except (OSError, ValueError):
            data = heritage_source(descriptor)
    if sha256(data) != descriptor['source_sha256']:
        raise ValueError('Source SHA-256 mismatch: ' + descriptor['path'])
    cache.mkdir(parents=True, exist_ok=True)
    if not cached.is_file():
        cached.write_bytes(data)
    return data


def restore_excerpt(descriptor, cache, offline=False):
    data = source_bytes(descriptor, cache, offline)
    if descriptor.get('transformation') == 'blank_comments_preserve_line_breaks':
        transformed = bytearray(data)
        for start, stop in descriptor['comment_byte_ranges']:
            if not 0 <= start <= stop <= len(transformed):
                raise ValueError('Invalid comment byte range')
            for pos in range(start, stop):
                if transformed[pos] not in (10, 13):
                    transformed[pos] = 32
        data = bytes(transformed)
    start = descriptor.get('byte_start', 0)
    stop = descriptor.get('byte_end', len(data))
    data = data[start:stop]
    if sha256(data) != descriptor['excerpt_sha256']:
        raise ValueError('Excerpt SHA-256 mismatch: ' + descriptor['path'])
    return data.decode('utf-8')


def reconstruct(value, cache, offline=False):
    if isinstance(value, dict):
        if set(value) == {'external_source'}:
            return restore_excerpt(value['external_source'], cache, offline)
        if set(value) == {'external_json_string'}:
            item = value['external_json_string']
            restored = reconstruct(item['value'], cache, offline)
            text = canonical(restored)
            if sha256(text.encode()) != item['sha256']:
                raise ValueError('Embedded JSON reconstruction mismatch')
            return text
        return {k: reconstruct(v, cache, offline) for k, v in value.items()}
    if isinstance(value, list):
        return [reconstruct(v, cache, offline) for v in value]
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        parser.error('Input and output must differ')
    if args.input.suffix == '.jsonl':
        rows = [reconstruct(json.loads(line), args.cache, args.offline)
                for line in args.input.read_text().splitlines() if line]
        text = ''.join(canonical(row) + '\n' for row in rows)
    else:
        value = reconstruct(json.loads(args.input.read_text()), args.cache, args.offline)
        text = json.dumps(value, ensure_ascii=False, indent=2) + '\n'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text)
    print(json.dumps({'output': args.output.name, 'sha256': sha256(text.encode())}))


if __name__ == '__main__':
    main()
