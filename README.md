# Be-rich

Quick helper: a script to scan the repository for configuration files and extract potential internal keys/secrets is available at `scripts/extract_keys.py`.

Usage:

```bash
python3 -m pip install -r requirements.txt
python3 -m pip install -r requirements.txt
python3 scripts/extract_keys.py --root .

Options:

- `--mask`: include `masked` fields in output (redacted values)
- `--validate`: include heuristic tags such as `stripe_secret_like`, `jwt_like`
- `--decodings`: attempt extra decodings (rot13, base64+gzip)

Example with all features:

```bash
python3 scripts/extract_keys.py --root . --mask --validate --decodings
```

Agent entrypoint:

```bash
python3 scripts/agent_entry.py --scan-root . --out output/agent_report.json --mask --validate --decodings --discover-domains
```

Options:
- `--discover-domains`: scan repository files for domain-like strings and run `detect_technologies` on them (results in `detect_discovered` in report).
```

Results are written to `output/keys_extracted.json`.