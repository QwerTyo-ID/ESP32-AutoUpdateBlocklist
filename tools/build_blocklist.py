#!/usr/bin/env python3
import re
import sys, os, math, urllib.request

HASH_BYTES = 5
MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME  = 0x100000001b3
U64 = (1 << 64) - 1

DEFAULT_SOURCES = [
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt',
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt',
    'https://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/domain.txt',
]

ADG = re.compile(r'^(@@)?\|\|([a-z0-9._-]+)\^?(\$.*)?$', re.I)

ALLOW_MISSING = False

def fnv(b: bytes) -> int:
    h = FNV_OFFSET
    for c in b:
        h = ((h ^ c) * FNV_PRIME) & U64
    return h & MASK

def norm(d: str) -> str:
    d = d.strip().lower().lstrip('*').lstrip('.').rstrip('.')
    return d[4:] if d.startswith('www.') else d

def read_source(src: str) -> str:
    if os.path.exists(src):
        return open(src, errors='ignore').read()
    print(f'  downloading {src} ...', file=sys.stderr)
    return urllib.request.urlopen(src, timeout=180).read().decode('utf-8', 'ignore')

def main():
    global ALLOW_MISSING
    args = [a for a in sys.argv[1:] if a != '--allow-missing']
    ALLOW_MISSING = '--allow-missing' in sys.argv[1:]
    out = args[0] if args else 'blocklist.bin'
    sources = args[1:] if len(args) > 1 else DEFAULT_SOURCES

    domains, allow = set(), set()
    skipped = 0
    for src in sources:
        try:
            data = read_source(src)
        except Exception as e:
            print(f'  !! FAILED to read {src}: {e}', file=sys.stderr)
            if not ALLOW_MISSING: sys.exit(1)
            continue
        for line in data.splitlines():
            line = line.split('#', 1)[0].strip() if not line.lstrip().startswith(('||', '@@')) else line.strip()
            if not line or line[0] in '!/[':
                continue
            m = ADG.match(line)
            if m:
                if m.group(3):
                    skipped += 1; continue
                (allow if m.group(1) else domains).add(norm(m.group(2)))
                continue
            if line.startswith(('||', '@@', '|')) or any(c in line for c in '^$*'):
                skipped += 1; continue
            parts = line.split()
            if parts[0] in ('0.0.0.0','127.0.0.1','::1','::'):
                entries = parts[1:]
            else:
                entries = parts if len(parts) == 1 else []
            for d in entries:
                d = norm(d)
                if '.' in d and ' ' not in d:
                    domains.add(d)
    if allow:
        before = len(domains); domains -= allow
        print(f'allowlisted      : {before - len(domains):,} removed ({len(allow):,} @@ rules)', file=sys.stderr)
    if skipped:
        print(f'skipped rules    : {skipped:,} (adblock syntax that a DNS hash list cannot express)', file=sys.stderr)

    hashes = sorted(fnv(d.encode()) for d in domains)
    collisions = len(hashes) - len(set(hashes))
    uniq = sorted(set(hashes))
    with open(out, 'wb') as f:
        for h in uniq:
            f.write(h.to_bytes(HASH_BYTES, 'little'))

    n, size = len(uniq), len(uniq) * HASH_BYTES
    print(f'source domains   : {len(domains):,}')
    print(f'hash entries     : {n:,}  ({HASH_BYTES}-byte / {HASH_BYTES*8}-bit)')
    print(f'collisions       : {collisions}  (domains sharing a hash -> over-block)')
    print(f'flash blob       : {size:,} bytes  ({size/1024/1024:.2f} MB)  -> {out}')
    print(f'lookup           : ~{math.ceil(math.log2(max(n,2)))} reads/query')

if __name__ == '__main__':
    main()
