#!/usr/bin/env python3
"""
IOC Extractor - extrae IOCs (IPs, dominios, emails, hashes) desde ficheros de texto o binarios (pcap fallback).
- Uso básico: python ioc_extractor.py -i input.txt -o report.json
- Opcional: si Scapy está disponible, intentará leer PCAPs y extraer payloads.
"""

from pathlib import Path
import re
import argparse
import json
import csv
import sys

# Regex patterns
RE_EMAIL = re.compile(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
RE_IPV4 = re.compile(r'\b(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}\b')
RE_DOMAIN = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b', re.IGNORECASE)
RE_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
RE_SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')

# Minimal printable string extractor for binaries
RE_PRINTABLE = re.compile(rb'[\x20-\x7E]{4,}')

# Optional scapy import for PCAP handling
try:
    from scapy.all import rdpcap, Raw
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

def extract_from_text(text: str):
    """Extracts IOCs from a text string and returns a dict of sets"""
    results = {
        "emails": set(),
        "ipv4": set(),
        "domains": set(),
        "md5": set(),
        "sha1": set(),
        "sha256": set(),
    }
    # Emails first (to avoid domain duplication handling if desired)
    for m in RE_EMAIL.findall(text):
        results["emails"].add(m.strip())
    for m in RE_IPV4.findall(text):
        results["ipv4"].add(m.strip())
    # Domains: avoid matching parts of other tokens by simple filter
    for m in RE_DOMAIN.findall(text):
        # Exclude if it looks like an IP accidentally matched, or a trailing punctuation
        # <-- CORRECTED: escape the backslash and single-quote properly
        candidate = m.strip().lower().rstrip('.,;:()[]\\\'"')
        if candidate and not RE_IPV4.match(candidate):
            results["domains"].add(candidate)
    for m in RE_MD5.findall(text):
        results["md5"].add(m.lower())
    for m in RE_SHA1.findall(text):
        results["sha1"].add(m.lower())
    for m in RE_SHA256.findall(text):
        results["sha256"].add(m.lower())
    return results

def strings_from_binary(data: bytes):
    """Extract printable strings from binary data (like `strings` utility)"""
    found = RE_PRINTABLE.findall(data)
    # decode ignoring errors
    return "\n".join(s.decode('utf-8', errors='ignore') for s in found)

def scan_file(path: Path):
    """Scan a single file, try to decode as text, fallback to binary strings.
       If file is a pcap and scapy is available, attempt to extract payloads."""
    aggregated_text = ""
    try:
        b = path.read_bytes()
    except Exception as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)
        return None

    # If scapy available and file endswith pcap-like, attempt pcap parse
    if SCAPY_AVAILABLE and path.suffix.lower() in ('.pcap', '.pcapng'):
        try:
            pkts = rdpcap(str(path))
            pieces = []
            for p in pkts:
                try:
                    # extract Raw payload if present
                    if Raw in p:
                        raw = bytes(p[Raw].load)
                        pieces.append(raw.decode('utf-8', errors='ignore'))
                except Exception:
                    continue
            aggregated_text = "\n".join(pieces)
        except Exception:
            # fallback to binary strings
            aggregated_text = strings_from_binary(b)
    else:
        # try decode as utf-8/latin-1 text
        for enc in ('utf-8', 'latin-1', 'cp1252'):
            try:
                aggregated_text = b.decode(enc)
                break
            except Exception:
                aggregated_text = ""
        if not aggregated_text:
            aggregated_text = strings_from_binary(b)
    return aggregated_text

def merge_results(accum, new):
    for k, s in new.items():
        accum[k].update(s)

def to_serializable(results):
    return {k: sorted(list(v)) for k, v in results.items()}

def write_json(path, results):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(to_serializable(results), f, indent=2, ensure_ascii=False)

def write_csv(path, results):
    # flatten into rows: type, value
    rows = []
    for k, vals in results.items():
        for v in sorted(vals):
            rows.append({'ioc_type': k, 'value': v})
    keys = ['ioc_type', 'value']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

def main():
    p = argparse.ArgumentParser(description='IOC Extractor - extract IOCs from files (text or binary/pcap).')
    p.add_argument('-i', '--input', required=True, nargs='+', help='Input file(s) or directories to scan.')
    p.add_argument('-o', '--output', required=False, default='ioc_report.json', help='Output JSON or CSV path (.json or .csv).')
    p.add_argument('--no-dedupe', action='store_true', help='Disable deduplication across files (not recommended).')
    args = p.parse_args()

    input_paths = []
    for ip in args.input:
        pth = Path(ip)
        if not pth.exists():
            print(f"Warning: {ip} does not exist, skipping.", file=sys.stderr)
            continue
        if pth.is_dir():
            for f in pth.rglob('*'):
                if f.is_file():
                    input_paths.append(f)
        else:
            input_paths.append(pth)

    accum = {
        "emails": set(),
        "ipv4": set(),
        "domains": set(),
        "md5": set(),
        "sha1": set(),
        "sha256": set(),
    }

    per_file = {}
    for f in input_paths:
        text = scan_file(f)
        if text is None:
            continue
        extracted = extract_from_text(text)
        per_file[str(f)] = to_serializable(extracted)
        merge_results(accum, extracted)

    # choose output format based on extension
    out_path = Path(args.output)
    if out_path.suffix.lower() == '.csv':
        write_csv(str(out_path), accum)
        print(f"CSV written to {out_path}")
    else:
        # write both aggregated and per-file
        payload = {
            "summary": to_serializable(accum),
            "per_file": per_file,
        }
        with open(str(out_path), 'w', encoding='utf-8') as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        print(f"JSON written to {out_path} (summary + per_file)")

if __name__ == '__main__':
    main()
