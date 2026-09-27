#!/usr/bin/env python3
"""Rebuild a seeded, offline end-to-end fixture; never imports the decoder."""
import argparse
import base64
from collections import Counter
import csv
import gzip
import hashlib
import io
import itertools
from pathlib import Path
import random

from encoders import ENCODERS, affine, caesar, columnar, rail, substitute, vig

ROOT = Path(__file__).resolve().parents[1]
SEED = 20260927
FIELDS = ['group', 'name', 'mode', 'expectation', 'forward_steps', 'input_b64', 'expected_b64', 'method']


def payloads(count, rng, prose):
    texts = []
    wrappers = ['flag', 'KAP', 'HTB', 'CTF', 'picoCTF', 'THM']
    topics = ['hidden_message', 'decode_the_layers', 'secret_letter', 'midnight_packet',
              'follow_the_steps', 'keep_the_bytes', 'open_the_door', 'search_the_room']
    for i in range(count):
        if i % 4 in (0, 1):
            texts.append(f'{wrappers[i % len(wrappers)]}{{{rng.choice(topics)}_{rng.getrandbits(48):012x}}}'.encode())
        elif i % 4 == 2:
            # Full paragraphs from a book absent from model training.
            texts.append(prose[(i * 17) % len(prose)])
        else:
            value = [f'print("message {i}: hello world")\n',
                     f'{{"message":"hello world","id":{i},"active":true}}',
                     f'  The message arrived at the old house at midnight. Case {i}.  \n',
                     f'https://example.org/message/{i}?mode=read'][i // 4 % 4]
            texts.append(value.encode())
    return texts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--per-method', type=int, default=160, help='cases per transform / statistical cipher (default 160)')
    args = parser.parse_args()
    if not 8 <= args.per_method <= 2000:
        parser.error('--per-method must be between 8 and 2000')
    count = args.per_method
    rng = random.Random(SEED)
    prose = gzip.decompress((ROOT / 'benchmarks/prose.txt.gz').read_bytes()).splitlines()
    texts = payloads(count, rng, prose)
    with gzip.open(ROOT / 'benchmarks/regression.tsv.gz', 'rt', encoding='utf-8', newline='') as fh:
        rows = list(csv.DictReader(fh, delimiter='\t'))
    for row in rows:
        row['method'] = 'legacy:' + row['group']
    names = {r['name'] for r in rows}

    def add(group, name, plain, steps=(), encoded=None, method=None, deep=False, expectation='recover'):
        assert name not in names, name
        names.add(name)
        data = plain if encoded is None else encoded
        if encoded is None:
            for step in steps:
                data = ENCODERS[step](data)
        assert 0 < len(data) <= 1024 * 1024, (name, len(data))
        rows.append(dict(zip(FIELDS, [group, name, 'deep' if deep else 'normal', expectation,
                    '|'.join(steps), base64.b64encode(data).decode(), base64.b64encode(plain).decode(),
                    method or (steps[0] if steps else group)])))

    for i, plain in enumerate(texts):
        add('plaintext', f'new-plain-{i}', plain)
    for method, encoder in ENCODERS.items():
        for i, plain in enumerate(texts):
            if method == 'morse':
                # Morse does not represent case; fixtures use its supported alphabet.
                plain = f'THE SECRET MESSAGE HAS ARRIVED AT THE OLD HOUSE CASE {i}'.encode()
            add('single', f'single-{method}-{i:04d}', plain, (method,))

    profiles = [(m, depths) for m, depths in [
        ('base64', (2, 3, 5, 8, 12, 16)), ('base32', (2, 3, 5, 8)),
        ('hex', (2, 3, 5)), ('base85', (2, 3, 5, 8)), ('ascii85', (2, 3, 5)),
        ('url', (2, 3, 5)), ('gzip', (2, 3, 5)), ('zlib', (2, 3, 5)),
        ('bzip2', (2, 3, 5)), ('xz', (2, 3, 5)), ('unicode', (2, 3)),
        ('quoted-printable', (2, 3)), ('binary', (2, 3)), ('hex-escapes', (2, 3))]]
    for method, depths in profiles:
        for i, plain in enumerate(texts):
            depth = depths[i % len(depths)]
            add('repeated', f'repeat-{method}-{i:04d}', plain, (method,) * depth, method=method)

    recipes = [
        ('base64', 'rot13', 'caesar7', 'base32', 'binary'),
        ('base64', 'base64', 'base64', 'binary', 'xor42', 'decimal'),
        ('gzip', 'base64', 'hex'), ('base32', 'caesar7', 'base64', 'url'),
        ('hex', 'xorFF', 'base64'), ('base64', 'reverse', 'base32'),
        ('base64', 'base64', 'rot47', 'binary'), ('xz', 'base85', 'html'),
        ('bzip2', 'base64-url', 'unicode'), ('zlib', 'base32', 'hex-escapes'),
        ('base58', 'base64', 'url'), ('ascii85-adobe', 'hex', 'base64'),
        ('html-hex', 'gzip', 'base85'), ('decimal', 'base64', 'rot13', 'base32'),
        ('octal', 'xorFF', 'base64'), ('base32-lower', 'reverse', 'base64'),
        ('url-form', 'base64', 'atbash', 'base64'), ('hex-list', 'gzip', 'base32'),
        ('quoted-printable-soft', 'zlib', 'base64'), ('unicode-long', 'base85', 'hex'),
        ('base64', 'base32', 'base85', 'base64'), ('rot47', 'gzip', 'hex'),
        ('atbash', 'xz', 'base64'), ('reverse', 'base58', 'base32'),
    ]
    for j, recipe in enumerate(recipes):
        for i, plain in enumerate(texts):
            add('mixed', f'chain-{j:02d}-{i:04d}', plain, recipe, method=f'chain-{j:02d}')
    for i in range(count):
        plain = f'THE LETTER CONTAINS A SECRET MESSAGE NUMBER {i}'.encode()
        add('mixed', f'chain-morse-{i:04d}', plain, ('morse', 'base64', 'gzip', 'base32'), method='morse-chain')

    for key in range(26):
        for i, plain in enumerate(texts[:8]):
            add('key-sweep', f'caesar-key-{key:02d}-{i}', plain, encoded=caesar(plain, key),
                steps=(f'caesar({key})',), method='caesar')
    for key in range(256):
        for i, plain in enumerate(texts[:4]):
            add('key-sweep', f'xor-key-{key:03d}-{i}', plain, encoded=bytes(b ^ key for b in plain),
                steps=(f'xor({key:02x})',), method='single-byte-xor')
    for a, b in itertools.product((1,3,5,7,9,11,15,17,19,21,23,25), range(26)):
        for i, plain in enumerate(texts[:2]):
            add('key-sweep', f'affine-key-{a:02d}-{b:02d}-{i}', plain, encoded=affine(plain, a, b),
                steps=(f'affine({a},{b})',), method='affine')

    for i in range(count):
        plain = prose[i % len(prose)]
        rails = 2 + i % 31
        add('advanced', f'rail-{i:04d}', plain, encoded=rail(plain, rails),
            steps=(f'rail({rails})',), method='rail-fence', deep=rails > 16)
        size = 2 + i % 11
        key = bytes(rng.randrange(65, 91) for _ in range(size))
        add('advanced', f'vigenere-{i:04d}', plain, encoded=vig(plain, key),
            steps=(f'vigenere({key.decode()})',), method='vigenere', deep=True)
        key = bytes(rng.randrange(256) for _ in range(size))
        add('advanced', f'repeating-xor-{i:04d}', plain,
            encoded=bytes(b ^ key[j % len(key)] for j, b in enumerate(plain)),
            steps=(f'repeating-xor({key.hex()})',), method='repeating-xor', deep=True)
        width = 2 + i % 5
        chars = list('ABCDEF'[:width]); rng.shuffle(chars); keyword = ''.join(chars)
        add('advanced', f'columnar-{i:04d}', plain, encoded=columnar(plain, keyword),
            steps=(f'columnar({keyword})',), method='columnar', deep=width > 4)
        seed = SEED + i
        add('advanced', f'substitution-{i:04d}', plain, encoded=substitute(plain, seed),
            steps=(f'substitution(seed={seed})',), method='substitution', deep=True)

    for i in range(count):
        size = 48 + i % 208
        random_bytes = bytes(rng.randrange(256) for _ in range(size))
        add('negative', f'random-bytes-{i:04d}', random_bytes, expectation='reject', method='random-bytes')
        digest = hashlib.sha256(random_bytes).hexdigest().encode()
        add('negative', f'hash-{i:04d}', digest, expectation='reject', method='hash-shaped')
        control = f'$argon2id$v=19$m=65536,t=3,p=4${i:04d}$'.encode() + digest
        add('negative', f'password-hash-{i:04d}', control, expectation='reject', method='password-hash')
        binary = b'\x89PNG\r\n\x1a\n' + random_bytes
        add('binary-output', f'binary-{i:04d}', binary, ('gzip', 'base64'), method='signature-only')

    buffer = io.StringIO(newline='')
    writer = csv.DictWriter(buffer, fieldnames=FIELDS, delimiter='\t', lineterminator='\n')
    writer.writeheader(); writer.writerows(rows)
    path = ROOT / 'benchmarks/cases.tsv.gz'
    path.write_bytes(gzip.compress(buffer.getvalue().encode(), mtime=0))
    counts = Counter(r['group'] for r in rows)
    unique = len({(r['input_b64'], r['expected_b64'], r['expectation']) for r in rows})
    print(f'{len(rows):,} cases; {unique:,} unique input/expected pairs; seed {SEED}')
    print(dict(sorted(counts.items())))
    print(f'Fixture SHA256: {hashlib.sha256(path.read_bytes()).hexdigest()}')


if __name__ == '__main__':
    main()
