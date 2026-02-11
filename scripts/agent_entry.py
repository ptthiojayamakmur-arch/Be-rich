#!/usr/bin/env python3
"""Agent entrypoint: orchestrate technology detection and config-key extraction.

Usage examples:
  python3 scripts/agent_entry.py --domain example.com --scan-root . --out output/agent_report.json --mask --validate --decodings
  python3 scripts/agent_entry.py --scan-root . --out output/agent_report.json --run-scan --mask
"""
import argparse
import json
import os
from typing import Any, Dict

from scripts.detect_technologies import detect_technologies
from scripts.extract_keys import find_files, scan_file
from scripts.dns_inspector import inspect_domain_dns, export_report as export_dns_report
import re


def discover_domains(root: str):
    """Scan files under root for domain-like strings and return a list of unique domains."""
    domain_re = re.compile(r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
    found = set()
    for dirpath, dirs, files in os.walk(root):
        # skip git
        if '.git' in dirpath.split(os.sep):
            continue
        for fname in files:
            path = os.path.join(dirpath, fname)
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    data = f.read()
            except Exception:
                continue
            for m in domain_re.findall(data):
                d = m.lower()
                if d.startswith('127.') or d.startswith('localhost'):
                    continue
                found.add(d)
    return sorted(found)


def main():
    ap = argparse.ArgumentParser(description="Agent entrypoint: detect technologies and extract keys")
    ap.add_argument("--domain", help="Domain to detect technologies for")
    ap.add_argument("--timeout", type=int, default=10, help="Timeout for network probes")
    ap.add_argument("--scan-root", default='.', help="Root path to scan for config files")
    ap.add_argument("--out", default='output/agent_report.json', help="Output JSON file")
    ap.add_argument("--mask", action='store_true', help="Mask sensitive values in scan output")
    ap.add_argument("--validate", action='store_true', help="Include heuristic validation tags")
    ap.add_argument("--decodings", action='store_true', help="Attempt additional decodings in scan")
    ap.add_argument("--run-detect", action='store_true', help="Run technology detection (requires --domain)")
    ap.add_argument("--discover-domains", action='store_true', help="Discover domains in files under --scan-root and run detection on them")
    ap.add_argument("--run-dns", action='store_true', help="Run DNS inspection for --domain or discovered domains")
    ap.add_argument("--run-scan", action='store_true', help="Run config scan")
    ap.add_argument("--verbose", action='store_true')
    args = ap.parse_args()

    report: Dict[str, Any] = {
        'detect': None,
        'scan': [],
        'meta': {
            'domain': args.domain,
            'scan_root': os.path.abspath(args.scan_root),
        }
    }

    # Run detection
    if args.run_detect:
        if not args.domain:
            raise SystemExit("--run-detect requires --domain")
        det = detect_technologies(args.domain, timeout=args.timeout, verbose=args.verbose)
        report['detect'] = det

    # Run DNS inspection for the primary domain
    if args.run_dns:
        if args.domain:
            dnsr = inspect_domain_dns(args.domain, timeout=args.timeout)
            report['dns'] = {args.domain: dnsr}
        else:
            report['dns'] = {}


    # Discover domains in repo and run detection
    if args.discover_domains:
        domains = discover_domains(args.scan_root)
        report['meta']['discovered_domains'] = domains
        dets = {}
        for d in domains:
            dets[d] = detect_technologies(d, timeout=args.timeout, verbose=args.verbose)
        report['detect_discovered'] = dets
        if args.run_dns:
            dns_results = {}
            for d in domains:
                dns_results[d] = inspect_domain_dns(d, timeout=args.timeout)
            report['dns_discovered'] = dns_results

    # Run scan
    if args.run_scan:
        files = find_files(args.scan_root)
        scans = []
        for p in files:
            res = scan_file(p, do_decodings=args.decodings, do_validate=args.validate, do_mask=args.mask)
            if isinstance(res, dict) and res.get('items'):
                scans.append(res)
        report['scan'] = scans

    # If neither flag set, run both (safe default: run scan only if scan-root exists)
    if not args.run_detect and not args.run_scan:
        if args.domain:
            report['detect'] = detect_technologies(args.domain, timeout=args.timeout, verbose=args.verbose)
        files = find_files(args.scan_root)
        scans = []
        for p in files:
            res = scan_file(p, do_decodings=args.decodings, do_validate=args.validate, do_mask=args.mask)
            if isinstance(res, dict) and res.get('items'):
                scans.append(res)
        report['scan'] = scans

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    print('Agent run complete. Report written to', args.out)


if __name__ == '__main__':
    main()
