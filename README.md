# Cryptid

**Automatic layered decoding for the Linux terminal.**

By **AADHIL FAZAL** · [@aadhilfazal](https://github.com/aadhilfazal)

Give Cryptid encoded text or a file. It searches for English plaintext and CTF
flags such as `flag{...}`, `KAP{...}` and `HTB{...}`, and explains the byte
transformations that led to its answer. You do not need to know the layer count,
the method order, or a Caesar/XOR key.

Python **3.10+**. Linux. Standard library only. Offline: no AI model, API key,
network request, telemetry, or third-party Python runtime dependency.

## Install

Extract `cryptid.zip`, open a terminal in the extracted `cryptid` directory,
then run:

```bash
sh install.sh
```

The installer places the command in `~/.local/bin/cryptid` and a private copy of
the application in `~/.local/share/cryptid/`. It does not modify system Python or
need `sudo`. It prints a PATH line if your shell needs one. The extracted folder
can be moved afterwards. An optional install prefix is supported:

```bash
sh install.sh "$HOME/tools"
```

That installs to `$HOME/tools/bin/cryptid`. Each installation is versioned so a
failed copy leaves the previous command intact. Older copies in the application's
own `share/cryptid` directory can be removed manually after a successful update.

You can also run without installing:

```bash
python3 cryptid.py 'aGVsbG8gd29ybGQ='
python3 -m cryptid -f examples/mixed_layers.txt
```

An optional `pyproject.toml` installation is supported with `pip` inside a virtual
environment. The shell installer works without pip, setuptools, or internet access.

## Use

```bash
cryptid 'aGVsbG8gd29ybGQ='
cryptid -f secret.txt
cryptid -f secret.txt --deep -v
cryptid -f secret.txt -o answer.txt --report trace.txt
printf '%s' 'aGVsbG8gd29ybGQ=' | cryptid -d
```

These respectively analyse a string, read a file, search more thoroughly, save
the recovered bytes and a report, and send only recovered bytes through stdout.
Input files and piped bytes are never stripped. Encoding grammar may consume
whitespace inside an encoded representation, but decoded bytes are preserved.
No newline is automatically appended to raw output or saved answers.

The author watermark appears on every normal result, report, help and version
screen. In `-d` mode it appears on **stderr** so stdout stays byte-exact.

### Switches

| Switch | Purpose |
| --- | --- |
| `-f, --file FILE` | Read text or binary data from a file. |
| `-o, --output FILE` | Save the selected recovered bytes exactly. |
| `-d, --decode-only` | Raw recovered output on stdout; watermark/errors on stderr. |
| `-v, --verbose` | Intermediate previews and step evidence. |
| `--deep` | Larger search budgets and statistical substitution solving. |
| `--top N` | Up to 1–10 ranked candidates; default 3. |
| `--report FILE` | A readable report with the selected result and detailed trace. |
| `--list` | List supported methods and limits. |
| `-h, --help` | Usage help. |
| `-V, --version` | Version and author. |

There are intentionally no public time/depth switches, manual recipe switches,
colour switches, JSON output, GUI, modern decryption, or hash-cracking features.
Reports and ordinary terminal output use plain text.

### Try the included examples

```bash
cryptid -f examples/mixed_layers.txt -v
cryptid -f examples/xor_layers.txt -v
cryptid -f examples/base64_repeated.txt
```

The first was encoded as Base64 → ROT13 → Caesar → Base32 → binary.
Cryptid works backwards. ROT13 and Caesar can combine into one shift, so the
recovery route can have fewer steps than the original encoding history.
The second exercises Base64 ×3 → binary → XOR → decimal byte values.
Each sample has a neighbouring `.expected` file with the exact original bytes.

## How it works

1. Strict decoders check syntax and, where possible, canonical round trips or
   compression integrity.
2. A best-first search explores actual byte transformations. Valid encoding
   paths take priority over expensive cipher guesses.
3. Caesar and single-byte XOR candidates are tested automatically. A candidate
   can be promising because it contains **another encoding**, not just English.
4. The engine repeats decoders as needed. State deduplication avoids cycles such
   as repeatedly applying ROT13 or reversing bytes back and forth.
5. English word/quadgram statistics, recognised flag wrappers, structured-text
   parsing and file signatures rank the results. The displayed evidence is a
   heuristic assessment, not an invented probability of correctness.

No input is executed. Python-like text is parsed only to recognise its shape.
Archives/executables are identified as binary output, not extracted or run.

## Coverage

**Encodings:** Base64 and URL-safe Base64, Base32, hex and byte-escape forms,
Base58 (Bitcoin alphabet), Base85, Ascii85, binary byte groups, decimal and octal
byte lists, URL/form encoding, HTML entities, Unicode escapes, quoted-printable
and Morse.

**Compression:** gzip, zlib, bzip2 and xz, with bounded decompression and integrity
checks. Concatenated streams, trailing bytes and truncated streams are rejected.

**Classical ciphers:** Caesar/ROT13, ROT47, Atbash, reversed bytes, single-byte
XOR, Affine, standard Rail Fence, Vigenère, repeating-key XOR and bounded columnar
transposition. `--deep` also attempts substitution recovery through annealing.

**Advanced limits:** Vigenère needs at least 60 letters; repeating-key XOR needs
at least 80 bytes. Substitution needs at least 160 letters and is experimental.
Rail Fence searches standard offset-zero zigzags, up to 16 rails normally or 32
with `--deep`. Columnar transposition searches 2–4 columns normally or 2–6 with
`--deep`, without padding. Long/unknown keywords, nonstandard layouts, unusual
alphabets and very short ciphertexts can remain unresolved. Statistical attacks
assume English; they are not exhaustive key recovery guarantees.

## Results and limits

| Status | Meaning |
| --- | --- |
| `ALREADY-PLAINTEXT` | Input looks readable; returned unchanged. |
| `LIKELY-PLAINTEXT` | A strong candidate was found. Check the evidence and context. |
| `DECODED-BINARY` | A recognised file signature was recovered; not plaintext. |
| `AMBIGUOUS` | Some readable text appeared, but evidence is insufficient. |
| `UNRESOLVED` | Supported methods did not find convincing plaintext. |
| `INCOMPLETE` | An internal search budget was reached without a strong answer. |

Readability does not prove all layers are gone. A flag wrapper does not validate
the flag against a CTF server. Different histories can produce the same bytes.
Hashes may resemble hex-encoded data; digest length alone never identifies a hash
algorithm. Modern ciphertext cannot generally be identified or recovered without
additional information. Cryptid reports these cases rather than fabricating text.

Input is capped at **1 MiB**; each decoded blob at **4 MiB**. Normal/deep modes use
7/35-second internal search budgets, 500/2400 expanded states, 64/128 layers and
24/48 MiB of retained candidate bytes. Scoring caches and interpreter overhead
are additional memory. Individual decoders may finish slightly after the clock
budget. Cipher work has smaller input caps. Budgets are safeguards, not required
user settings; `--deep` expands the search when normal mode is insufficient.

English prose, technical text and recognised CTF flags are the primary target.
Non-English Unicode bytes are preserved through decoders but English scoring can
fail to recognise their meaning. Cryptid prioritises strong syntax; it does not
enumerate every arbitrary combination of transformations.

Exit codes: **0** selected plaintext/binary result; **1** unresolved or ambiguous;
**2** usage/input/file error; **3** incomplete search; **130** interruption.
`-d` and `-o` emit selected bytes only for status 0. On unresolved input, inspect
the console/report for partial results. Output and report paths must differ from
each other and from the input file. Writing an existing destination replaces it
atomically; use a new filename when you want to retain an older result.

## Tests and dataset

Run the regression suite and the release-critical benchmark:

```bash
python3 -m unittest discover -s tests -v
python3 benchmarks/evaluate.py --core
```

Run the full evaluation (several minutes or longer, depending on your CPU):

```bash
python3 benchmarks/evaluate.py --workers 6 --report benchmarks/RESULTS.md --details benchmarks/results.tsv
```

The **17,040-case** dataset contains **16,705 unique input/expected pairs**.
It includes 160 cases per encoding variant, varied classical keys, 25 mixed-layer
recipes, repeated formats, every Caesar and single-byte XOR key, every Affine
key, negative controls, and 160 cases each for Rail Fence, Vigenere, repeating-key
XOR, columnar transposition, and substitution. All supplied keys are used only by
the independent forward generator; the solver receives the ciphertext alone.

Exact original bytes are required for a pass. Failed and ambiguous cases are
retained and listed in [benchmarks/RESULTS.md](benchmarks/RESULTS.md), with one
result row per case in `benchmarks/results.tsv`. A full run returns exit code 1
if any case fails; this intentionally includes difficult statistical attacks.
The smaller `--core` selection and unit suite are the CI release checks.

On the shipped fixture, **16,609/17,040 outcomes were correct (97.47%)**, including
all 496 negative controls. The 431 unsuccessful cases include unresolved inputs
and incorrect statistical guesses. All 49 regression tests and 15 core cases pass.

The fixture and its generation inputs are included. Regenerate it offline with:

```bash
python3 benchmarks/generate.py
```

See [benchmarks/DATASET.md](benchmarks/DATASET.md) for exact coverage, source
attribution, duplicate counts and limitations. The bundled scoring model is
unchanged and was not trained on this evaluation text. The results describe this
development dataset, not guaranteed accuracy on unknown CTF challenges.

The checked-in GitHub workflow runs the tests on Linux/Python 3.10-3.14 when
uploaded to a repository. These CI jobs have not been run on GitHub as part of
this local release. See [VALIDATION.md](VALIDATION.md) for actual local checks.

## Project structure

| File | Why it exists |
| --- | --- |
| `cryptid/engine.py` | Searches and records decoding paths; enforces budgets. |
| `cryptid/codecs.py` | Strict reversible encodings and bounded decompressors. |
| `cryptid/ciphers.py` | Small-key brute force and statistical classical solvers. |
| `cryptid/scoring.py` | English, flag and structured-data evidence. |
| `cryptid/cli.py` | Agreed switches, author watermark, reports and exact output. |
| `cryptid/models.py` | Shared result and transformation data structures. |
| `cryptid/data/` | Bundled offline model and source attribution. |
| `tests/` | Regression tests. |
| `benchmarks/` | Independent forward encoders, 17,040-case dataset and full results. |
| `scripts/train_language.py` | Rebuilds language counts from supplied source files. |
| `scripts/build_release.py` | Rebuilds `cryptid.zip` and its checksums from clean source files. |

## License

MIT © 2026 AADHIL FAZAL. See [LICENSE](LICENSE). Language-data attribution is in
[cryptid/data/NOTICE.md](cryptid/data/NOTICE.md).
