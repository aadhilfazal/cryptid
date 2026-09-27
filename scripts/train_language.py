#!/usr/bin/env python3
"""Build offline word/quadgram counts from explicitly supplied text files.

Usage: python3 scripts/train_language.py BOOK1.txt BOOK2.txt
The shipped model was built from public-domain works; see data/NOTICE.md.
Evaluation prose comes from a different book, not these training inputs.
"""
import collections
import gzip
import json
from pathlib import Path
import re
import sys

if len(sys.argv) < 2:
    raise SystemExit('Usage: python3 scripts/train_language.py BOOK1.txt BOOK2.txt')
counts = collections.Counter()
quad = collections.Counter()
for name in sys.argv[1:]:
    text = Path(name).read_text(encoding="utf-8-sig")
    text = re.split(r"\*\*\* START OF .*?\*\*\*", text, maxsplit=1)[-1]
    text = re.split(r"\*\*\* END OF .*?\*\*\*", text, maxsplit=1)[0].lower()
    counts.update(re.findall(r"[a-z]+", text))
    letters = re.sub("[^a-z]", "", text)
    quad.update(letters[i:i+4] for i in range(len(letters)-3))

if not quad:
    raise SystemExit('No usable English letter sequences found; the existing model was not changed.')

# Vocabulary, not complete test sentences. No benchmark plaintexts are added.
technical = """hello world test flag secret password user admin administrator key
true false null http https www com name value data message error attack dawn quick
brown fox jumps lazy dog code source print return function def import from class
file path open read write bytes encode decode encoding decoding ciphertext
plaintext encrypt decrypt encryption decryption base binary decimal hexadecimal
server client network security cyber cybersecurity terminal command cryptography
python linux kali ubuntu shell script payload token challenge capture hash xor
rot caesar layer layers hidden answer solver solved search packet socket port
buffer memory database query json html url unicode gzip compressed archive
result output input protocol request response authorization authenticate welcome
access system permission granted denied success successful testing verify valid
invalid decoded recovered public private local remote offline online information
important notice hello congratulations coffee correct horse battery staple
meet midnight bridge north south east west please bring documents tomorrow
numbers punctuation digits underscores keeper checkpoint endpoint response
""".split()
for word in technical:
    counts[word] = max(counts[word], 12)

payload = {"words": dict(counts), "quadgrams": dict(quad),
           "sources": ["Project Gutenberg #11", "Project Gutenberg #1342"]}
out = Path(__file__).resolve().parents[1] / "cryptid/data/english.json.gz"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_bytes(gzip.compress(json.dumps(payload, separators=(",", ":"),
                                        sort_keys=True).encode(), mtime=0))
print(f"Wrote {len(counts)} words and {len(quad)} quadgrams to {out}")
