#!/usr/bin/env python3
"""Simple extractor to find config files and extract potential internal keys/secrets.

Usage:
  python3 scripts/extract_keys.py --root .

Outputs `output/keys_extracted.json` with structured results.
"""
import os
import re
import json
import argparse
import base64
import binascii
import codecs

try:
    import yaml
except Exception:
    yaml = None

SENSITIVE_NAME_RE = re.compile(r"(?i)(key|secret|token|pass|private|credential|pw|api|auth)")
BASE64_RE = re.compile(r'^[A-Za-z0-9+/=\n]+$')

def is_base64(s: str) -> bool:
    s = s.strip()
    if len(s) % 4 != 0:
        return False
    return bool(BASE64_RE.match(s))

def try_decode(value: str):
    decodings = []
    v = value.strip()
    # remove common wrappers
    if v.startswith('ENC(') and v.endswith(')'):
        v = v[4:-1]
        decodings.append({'method': 'strip_wrapper', 'result': v})

    # base64
    try:
        if is_base64(v):
            b = base64.b64decode(v)
            try:
                decodings.append({'method': 'base64', 'result': b.decode('utf-8')})
            except Exception:
                decodings.append({'method': 'base64', 'result': repr(b)})
    except Exception:
        pass

    # hex
    if re.fullmatch(r'[0-9a-fA-F]+', v) and len(v) % 2 == 0:
        try:
            b = binascii.unhexlify(v)
            try:
                decodings.append({'method': 'hex', 'result': b.decode('utf-8')})
            except Exception:
                decodings.append({'method': 'hex', 'result': repr(b)})
        except Exception:
            pass

    return decodings


def try_additional_decodings(v: str):
    extras = []
    # rot13 (simple text obfuscation)
    try:
        rot = codecs.decode(v, 'rot_13')
        if rot != v:
            extras.append({'method': 'rot13', 'result': rot})
    except Exception:
        pass

    # base64 -> gzip
    try:
        if is_base64(v):
            raw = base64.b64decode(v)
            try:
                import gzip
                out = gzip.decompress(raw)
                try:
                    extras.append({'method': 'base64+gzip', 'result': out.decode('utf-8')})
                except Exception:
                    extras.append({'method': 'base64+gzip', 'result': repr(out)})
            except Exception:
                pass
    except Exception:
        pass

    return extras


def validate_value(name: str, value: str):
    """Return list of heuristic tags indicating likely types or confidence."""
    tags = []
    v = value.strip()
    # common prefixes
    if v.startswith('sk_live') or v.startswith('sk_'):
        tags.append('stripe_secret_like')
    if v.startswith('pk_live') or v.startswith('pk_'):
        tags.append('stripe_pub_like')
    if v.startswith('whsec'):
        tags.append('webhook_secret_like')
    if len(v) >= 32 and re.search(r'[A-Za-z0-9]{20,}', v):
        tags.append('long_token_like')
    if re.fullmatch(r'[A-Za-z0-9\-_.]{16,}', v) and any(ch.isalpha() for ch in v) and any(ch.isdigit() for ch in v):
        tags.append('alnum_token_like')
    if name.lower().endswith('password') or 'pw' in name.lower() or 'db_password' in name.lower():
        tags.append('password')
    if 'jwt' in name.lower() or (v.count('.') == 2 and len(v.split('.')[0]) > 0):
        tags.append('jwt_like')
    return tags


def mask_value(v: str, keep=4):
    if not v:
        return v
    if len(v) <= keep * 2 + 3:
        return v[0:keep] + '...' + v[-keep:]
    return v[0:keep] + '...' + v[-keep:]

def parse_env_file(path):
    entries = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                k, v = line.split('=', 1)
                entries.append((k.strip(), v.strip()))
    return entries

def scan_file(path, do_decodings=False, do_validate=False, do_mask=False):
    results = []
    name = os.path.basename(path)
    try:
        if name.endswith('.env') or 'env' in name:
            entries = parse_env_file(path)
        elif name.endswith('.json'):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            entries = []
            def walk_json(obj, prefix=''):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        walk_json(v, prefix + k + '.')
                elif isinstance(obj, list):
                    for i, it in enumerate(obj):
                        walk_json(it, f"{prefix}{i}.")
                else:
                    entries.append((prefix.rstrip('.'), str(obj)))
            walk_json(data)
        elif (name.endswith('.yml') or name.endswith('.yaml')) and yaml:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                data = yaml.safe_load(f)
            entries = []
            def walk(obj, prefix=''):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        walk(v, prefix + k + '.')
                elif isinstance(obj, list):
                    for i, it in enumerate(obj):
                        walk(it, f"{prefix}{i}.")
                else:
                    entries.append((prefix.rstrip('.'), str(obj)))
            walk(data)
        else:
            # fallback: try parse as env-like
            entries = parse_env_file(path)
    except Exception as e:
        return {'path': path, 'error': str(e)}

    # filter sensitive names
    found = []
    seen = set()
    for k, v in entries:
        if k and SENSITIVE_NAME_RE.search(k):
            key = (k, v)
            if key in seen:
                continue
            seen.add(key)
            item = {'name': k, 'raw_value': v}
            decs = []
            decs.extend(try_decode(v))
            if do_decodings:
                decs.extend(try_additional_decodings(v))
            item['decodings'] = decs
            if do_validate:
                item['tags'] = validate_value(k, v)
            if do_mask:
                item['masked'] = mask_value(v)
            found.append(item)
    return {'path': path, 'items': found}

def find_files(root):
    patterns = ('.env', '.env.example', '.json', '.yml', '.yaml')
    matches = []
    for dirpath, dirs, files in os.walk(root):
        # skip .git
        if '.git' in dirpath.split(os.sep):
            continue
        for f in files:
            for p in patterns:
                if f.endswith(p) or f == p:
                    matches.append(os.path.join(dirpath, f))
                    break
    return matches

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default='.', help='Root path to scan')
    ap.add_argument('--out', default='output/keys_extracted.json')
    ap.add_argument('--mask', action='store_true', help='Include masked value in output')
    ap.add_argument('--validate', action='store_true', help='Include heuristic validation tags')
    ap.add_argument('--decodings', action='store_true', help='Attempt additional decodings (rot13, base64+gzip)')
    args = ap.parse_args()

    files = find_files(args.root)
    results = []
    for p in files:
        res = scan_file(p, do_decodings=args.decodings, do_validate=args.validate, do_mask=args.mask)
        # include only if items found
        if isinstance(res, dict) and res.get('items'):
            results.append(res)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump({'scanned_root': os.path.abspath(args.root), 'results': results}, f, indent=2)

    print('Done. Results written to', args.out)

if __name__ == '__main__':
    main()
