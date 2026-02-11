"""DNS inspection utilities: enumerates DNS records, checks SPF/DMARC/DKIM,
WHOIS lookup, DNSSEC presence, zone transfer tests, certificate transparency lookups,
and basic passive DNS via crt.sh.

Functions:
- inspect_domain_dns(domain, timeout=5) -> dict
- export_report(report: dict, json_path: str, txt_path: str)
"""
from typing import Dict, Any, List
import json
import requests
import socket
import subprocess
import time

try:
    import dns.resolver
    import dns.query
    import dns.exception
    import dns.zone
except Exception:
    dns = None


def _safe_resolve(domain: str, rdtype: str, timeout: int = 5) -> List[str]:
    if dns is None:
        return []
    answers = []
    try:
        r = dns.resolver.resolve(domain, rdtype, lifetime=timeout)
        for rr in r:
            answers.append(str(rr).strip())
    except Exception:
        pass
    return answers


def inspect_domain_dns(domain: str, timeout: int = 5) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        'domain': domain,
        'records': {},
        'spf': None,
        'dmarc': None,
        'dkim_selectors': [],
        'whois': None,
        'dnssec': {'has_dnskey': False, 'has_ds': False},
        'axfr': {},
        'crtsh': [],
        'passive_dns': [],
        'errors': []
    }

    # Basic record types
    types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'CAA', 'NAPTR']
    for t in types:
        vals = _safe_resolve(domain, t, timeout=timeout)
        result['records'][t] = vals

    # DNSSEC: check DNSKEY and DS
    if dns is not None:
        try:
            dnskey = _safe_resolve(domain, 'DNSKEY', timeout=timeout)
            ds = _safe_resolve(domain, 'DS', timeout=timeout)
            result['dnssec']['has_dnskey'] = bool(dnskey)
            result['dnssec']['has_ds'] = bool(ds)
        except Exception as e:
            result['errors'].append(f'dnssec check error: {e}')

    # SPF: look for v=spf1 in TXT
    txts = result['records'].get('TXT', [])
    for t in txts:
        if 'v=spf1' in t.lower():
            result['spf'] = t
            break

    # DMARC: _dmarc.domain TXT
    dmarc = _safe_resolve(f'_dmarc.{domain}', 'TXT', timeout=timeout)
    if dmarc:
        result['dmarc'] = dmarc

    # DKIM: try detect any TXT with v=DKIM1 in domain TXT and discovered subdomains
    for t in txts:
        if 'v=dkim1' in t.lower():
            result['dkim_selectors'].append({'selector': None, 'record': t})

    # For a better DKIM scan, try common selectors found in examples
    common_selectors = ['default', 'selector1', 'google', 's1', 's2']
    for sel in common_selectors:
        selname = f'{sel}._domainkey.{domain}'
        rec = _safe_resolve(selname, 'TXT', timeout=timeout)
        if rec:
            result['dkim_selectors'].append({'selector': sel, 'record': rec})

    # WHOIS (best-effort)
    try:
        # try python-whois if available
        import whois as _whois
        try:
            w = _whois.whois(domain)
            result['whois'] = dict(w)
        except Exception:
            result['whois'] = None
    except Exception:
        # fallback to system whois
        try:
            out = subprocess.check_output(['whois', domain], stderr=subprocess.DEVNULL, timeout=10, text=True)
            result['whois'] = out.splitlines()
        except Exception:
            result['whois'] = None

    # Zone transfer attempts (AXFR) against NS
    ns = result['records'].get('NS', [])
    if dns is not None:
        for n in ns:
            n = n.rstrip('.')
            axfr_ok = False
            try:
                z = dns.query.xfr(n, domain, lifetime=timeout)
                # try to iterate one RR
                for _ in z:
                    axfr_ok = True
                    break
            except Exception as e:
                result['axfr'][n] = {'ok': False, 'error': str(e)}
            else:
                result['axfr'][n] = {'ok': axfr_ok}

    # Certificate Transparency: query crt.sh
    try:
        url = f'https://crt.sh/?q={domain}&output=json'
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            try:
                j = r.json()
                # extract common_name and name_value
                for item in j:
                    cn = item.get('common_name')
                    nv = item.get('name_value')
                    result['crtsh'].append({'issuer_ca_id': item.get('issuer_ca_id'), 'common_name': cn, 'name_value': nv})
            except Exception:
                result['crtsh'] = []
    except Exception:
        pass

    # Passive DNS: use crt.sh name_value entries as passive hostnames
    for c in result['crtsh']:
        nv = c.get('name_value')
        if nv:
            for part in str(nv).split('\n'):
                p = part.strip()
                if p and p.endswith(domain):
                    result['passive_dns'].append(p.lower())

    # De-dup lists
    for k in ['passive_dns']:
        result[k] = sorted(list(set(result[k])))

    # Export summary
    return result


def export_report(report: Dict[str, Any], json_path: str, txt_path: str = None):
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    if txt_path:
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write(json.dumps(report, indent=2))
