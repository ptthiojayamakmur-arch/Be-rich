# Be-rich

Quick helper: a script to scan the repository for configuration files and extract potential internal keys/secrets is available at `scripts/extract_keys.py`.

Usage:

```bash
python3 -m pip install -r requirements.txt
python3 -m pip install -r requirements.txt
python3 scripts/extract_keys.py --root .

Options:


Example with all features:

```bash
python3 scripts/extract_keys.py --root . --mask --validate --decodings
```

Agent entrypoint:

```bash
python3 scripts/agent_entry.py --scan-root . --out output/agent_report.json --mask --validate --decodings --discover-domains
```

Options:
- `--run-dns`: run DNS inspection (records, SPF/DMARC/DKIM, WHOIS, DNSSEC hints, AXFR attempts, certificate transparency via crt.sh)
DNS inspection exports are included in the aggregated report under `dns` (for primary `--domain`) and `dns_discovered` for discovered domains. Use `--run-dns --discover-domains` to run DNS checks for discovered domains.
```

Results are written to `output/keys_extracted.json`.