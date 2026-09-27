#!/usr/bin/env python3
"""Measure exact-byte top-1/top-5 recovery, rejected controls, and all failures."""
import argparse
import base64
from collections import defaultdict
import csv
from datetime import datetime, timezone
import gzip
import hashlib
import multiprocessing
import os
from pathlib import Path
import platform
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
csv.field_size_limit(2 * 1024 * 1024)
from cryptid.engine import solve
from cryptid import __version__

SUCCESS = {'likely-plaintext', 'already-plaintext', 'decoded-binary'}
CORE = {'mix-0-0', 'mix-1-0', 'mix-2-0', 'mix-3-0', 'mix-0-1', 'mix-2-1',
        'b64-0-16', 'b64-2-10', 'b32-0-8', 'affine', 'rail', 'vigenere',
        'repeating-xor', 'columnar', 'substitution'}
DETAIL_FIELDS = ['group', 'method', 'name', 'mode', 'expectation', 'correct', 'in_top5',
                 'status', 'seconds', 'route', 'limits', 'output_sha256', 'failure_preview']


def evaluate_row(row):
    data = base64.b64decode(row['input_b64'])
    expected = base64.b64decode(row['expected_b64'])
    item = {k: row.get(k, '') for k in DETAIL_FIELDS}
    try:
        result = solve(data, deep=row['mode'] == 'deep', top=5)
        if row['expectation'] == 'reject':
            exact = result.status not in SUCCESS
            found = exact
        else:
            exact = result.best.data == expected and result.status in SUCCESS
            found = any(c.data == expected for c in result.candidates)
        item.update(correct=int(exact), in_top5=int(found), status=result.status,
                    seconds=f'{result.elapsed:.6f}', route=' > '.join(s.name for s in result.best.steps),
                    limits=', '.join(result.limits), output_sha256=hashlib.sha256(result.best.data).hexdigest(),
                    failure_preview='' if exact else repr(result.best.data[:120]))
    except Exception as exc:
        item.update(correct=0, in_top5=0, status='error', seconds='0',
                    failure_preview=f'{type(exc).__name__}: {exc}')
    return item


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', action='store_true', help='release-critical regression cases')
    parser.add_argument('--group', help='comma-separated groups')
    parser.add_argument('--method', help='comma-separated method labels')
    parser.add_argument('--names-file', type=Path, help='text file with one case name per line')
    parser.add_argument('--limit-per-method', type=int, help='small, stratified trial run')
    parser.add_argument('--workers', type=int, default=1, help='parallel CPU workers (default 1)')
    parser.add_argument('--report', type=Path, help='write a Markdown report')
    parser.add_argument('--details', type=Path, help='write one TSV result row per case')
    args = parser.parse_args()
    if not 1 <= args.workers <= 32:
        parser.error('--workers must be between 1 and 32')
    fixture = ROOT / 'benchmarks/cases.tsv.gz'
    with gzip.open(fixture, 'rt', encoding='utf-8', newline='') as fh:
        rows = list(csv.DictReader(fh, delimiter='\t'))
    if args.core:
        rows = [r for r in rows if r['name'] in CORE]
    if args.group:
        rows = [r for r in rows if r['group'] in args.group.split(',')]
    if args.method:
        rows = [r for r in rows if r.get('method') in args.method.split(',')]
    if args.names_file:
        names = set(args.names_file.read_text().splitlines())
        rows = [r for r in rows if r['name'] in names]
    if args.limit_per_method:
        kept = []; counts = defaultdict(int)
        for row in rows:
            label = (row['group'], row['method'])
            if counts[label] < args.limit_per_method:
                kept.append(row); counts[label] += 1
        rows = kept
    if not rows:
        parser.error('selection matched no cases')
    source_hash = hashlib.sha256()
    for path in sorted((ROOT / 'cryptid').rglob('*.py')) + [ROOT / 'cryptid/data/english.json.gz']:
        source_hash.update(str(path.relative_to(ROOT)).encode() + b'\0' + path.read_bytes())
    stats = defaultdict(lambda: [0, 0, 0, 0.0])
    methods = defaultdict(lambda: [0, 0, 0, 0.0])
    failures = []; details = []
    start = time.monotonic()
    pool = multiprocessing.Pool(args.workers) if args.workers > 1 else None
    results = pool.imap_unordered(evaluate_row, rows, chunksize=1) if pool else map(evaluate_row, rows)
    handle = args.details.open('w', encoding='utf-8', newline='') if args.details else None
    writer = csv.DictWriter(handle, fieldnames=DETAIL_FIELDS, delimiter='\t', lineterminator='\n') if handle else None
    if writer:
        writer.writeheader()
    try:
        for i, item in enumerate(results, 1):
            for st in (stats[item['group']], methods[(item['group'], item['method'])]):
                st[0] += 1; st[1] += int(item['correct']); st[2] += int(item['in_top5']); st[3] += float(item['seconds'])
            if not item['correct']:
                failures.append(item)
            if writer:
                writer.writerow(item)
            if i % 100 == 0 or i == len(rows):
                if handle: handle.flush()
                print(f'{i}/{len(rows)} evaluated; {len(failures)} failures; elapsed {time.monotonic()-start:.1f}s', flush=True)
    finally:
        if pool:
            pool.close(); pool.join()
        if handle:
            handle.close()
    elapsed = time.monotonic() - start
    unique = len({(r['input_b64'], r['expected_b64'], r['expectation']) for r in rows})
    lines = [f'# Cryptid {__version__} evaluation', '',
        f'Run: {datetime.now(timezone.utc).isoformat(timespec="seconds")}.',
        f'Runtime: {platform.python_implementation()} {platform.python_version()}, {platform.system()} {platform.machine()}; {args.workers} workers.',
        f'Fixture SHA-256: `{hashlib.sha256(fixture.read_bytes()).hexdigest()}`.',
        f'Application source/model SHA-256: `{source_hash.hexdigest()}`.',
        f'Cases evaluated: **{len(rows):,}**, including **{unique:,} unique input/expected pairs**.', '',
        'Exact original-byte equality and a successful status are required for positive top-1 recovery.',
        'Negative controls pass only when the solver avoids declaring success. Top-5 presence does not prove recovery.',
        'Seconds below are summed solver elapsed times; worker overlap makes them different from wall time.', '',
        '| Group | Cases | Correct top-1 / rejection | In top-5 / rejection | Solver seconds |',
        '| --- | ---: | ---: | ---: | ---: |']
    for group, s in sorted(stats.items()):
        lines.append(f'| {group} | {s[0]} | {s[1]} | {s[2]} | {s[3]:.2f} |')
    correct = sum(s[1] for s in stats.values())
    lines += ['', f'**Total correct: {correct:,}/{len(rows):,} ({correct/len(rows):.2%}). Wall time: {elapsed:.2f}s.**', '',
        '## Per-method breakdown', '',
        '| Group | Method | Cases | Correct top-1 / rejection | In top-5 / rejection |',
        '| --- | --- | ---: | ---: | ---: |']
    for (group, method), s in sorted(methods.items()):
        lines.append(f'| {group} | {method} | {s[0]} | {s[1]} | {s[2]} |')
    lines += ['', '## Limits and provenance', '',
        'These are development tests, not a blind external accuracy estimate. Training uses Gutenberg #11 and #1342;',
        'evaluation prose comes from the separate #1661 snapshot. The model is not trained on this fixture.',
        'Some variants intentionally produce identical bytes (for example Base64 alphabets when no special characters occur).',
        'All methods, including unsuccessful statistical attacks, remain in the fixture and in the results.',
        'A binary signature result identifies a header only; it does not validate the complete file.', '',
        f'Failures: **{len(failures):,}**. Errors: **{sum(r["status"] == "error" for r in failures)}**.', '']
    if failures:
        lines += ['## Every failed case', '', '| Case | Method | Status |', '| --- | --- | --- |']
        for item in sorted(failures, key=lambda r: (r['group'], r['name'])):
            lines.append(f'| {item["name"]} | {item["method"]} | {item["status"]} |')
    report = '\n'.join(lines) + '\n'
    if args.report:
        args.report.write_text(report, encoding='utf-8')
    print(f'Total: {correct}/{len(rows)}; failures {len(failures)}; wall {elapsed:.2f}s', flush=True)
    return int(bool(failures))


if __name__ == '__main__':
    raise SystemExit(main())
