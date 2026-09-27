# Evaluation dataset

`cases.tsv.gz` contains **17,040 test cases** and **16,705 unique input/expected pairs**.
The first release includes a seeded generator, all generation inputs, and full results.
The fixture records exact expected bytes before any forward transformations. The generator
and its encoders never import Cryptid's decoding or search implementation.

| Group | Cases |
| --- | ---: |
| advanced | 806 |
| binary-output | 160 |
| heldout | 18 |
| key-sweep | 1856 |
| mixed | 4064 |
| negative | 496 |
| plaintext | 172 |
| repeated | 2272 |
| single | 7196 |

## What is varied

- 44 named single-transform variants have 160 new cases each, plus the original regression cases.
- 14 repeated-format profiles vary the layer count; Base64 reaches 16 layers.
- 25 mixed recipes include both requested examples and a Morse/compression chain.
- Every Caesar key (including identity), every single-byte XOR key, and all 312 valid Affine keys are exercised.
- Rail Fence covers 2-32 rails; columnar widths are 2-6 with shuffled read orders.
- Vigenere and repeating-key XOR use varied random keys of length 2-12.
- Substitution uses 160 seeded random alphabets on varied evaluation passages.
- Controls include random bytes, hash-shaped strings, password-hash envelopes, and binary signatures.
- Structured text, flags with varied bodies/case, prose, trailing newlines and surrounding spaces are included.

## How to read the results

A positive case passes only if the selected output exactly equals the original bytes and
the solver reports success. A negative case passes only when the solver does not report
success. Top-5 presence is a separate measure and can include uncertain candidates.
Failure rows remain in the dataset and in the reports. The full evaluation exits with code 1
if any case fails; `--core` selects the smaller release-critical regression gate.

335 rows overlap in input/expected bytes. Some format variants produce the same bytes
(such as standard and URL-safe Base64 with no special characters); historical cases are
also retained. The unique-pair count is supplied so these overlaps are visible.

This is a development dataset used to find and fix bugs. It is not a blind external
accuracy estimate. Simple encodings and difficult statistical attacks have separate rows
in the per-method report. Long unknown names, title lists, short samples, ambiguous
punctuation, and cipher keys outside the documented search ranges can remain unresolved.
An output with a recognised binary signature is not a validation of the complete file.

## Sources and separation from training

The unchanged offline model uses word/quadgram counts from Gutenberg #11 and #1342.
Evaluation prose is from the separate public-domain work *The Adventures of Sherlock
Holmes*, Gutenberg #1661. `prose.txt.gz` includes 320 ASCII-normalised excerpts sampled
from that snapshot; these include name-heavy passages and a contents list, intentionally
retained as difficult text. `regression.tsv.gz` retains all 304 original regression cases,
including 18 separately sampled excerpts from the same book. None of these answers or
evaluation excerpts are added to the model. Source snapshot hashes are in `SOURCE_HASHES.txt`.
Literary punctuation is normalised only when creating the fixture; the decoder preserves
the bytes it actually recovers.

## Reproduce offline

```bash
python3 benchmarks/generate.py
python3 benchmarks/evaluate.py --workers 6 --report benchmarks/RESULTS.md --details benchmarks/results.tsv
```

Generation seed: `20260927`. All necessary fixture-generation inputs are included.
`--per-method N` changes the sample count; the checked-in fixture uses 160.
`--workers 1` evaluates sequentially. Parallel runs share CPU resources, so budget-limited
cases and elapsed times can differ across machines. There is no network request or AI call.

## Per-method case counts

| Group | Method | Cases |
| --- | --- | ---: |
| advanced | columnar | 160 |
| advanced | legacy:advanced | 6 |
| advanced | rail-fence | 160 |
| advanced | repeating-xor | 160 |
| advanced | substitution | 160 |
| advanced | vigenere | 160 |
| binary-output | signature-only | 160 |
| heldout | legacy:heldout | 18 |
| key-sweep | affine | 624 |
| key-sweep | caesar | 208 |
| key-sweep | single-byte-xor | 1024 |
| mixed | chain-00 | 160 |
| mixed | chain-01 | 160 |
| mixed | chain-02 | 160 |
| mixed | chain-03 | 160 |
| mixed | chain-04 | 160 |
| mixed | chain-05 | 160 |
| mixed | chain-06 | 160 |
| mixed | chain-07 | 160 |
| mixed | chain-08 | 160 |
| mixed | chain-09 | 160 |
| mixed | chain-10 | 160 |
| mixed | chain-11 | 160 |
| mixed | chain-12 | 160 |
| mixed | chain-13 | 160 |
| mixed | chain-14 | 160 |
| mixed | chain-15 | 160 |
| mixed | chain-16 | 160 |
| mixed | chain-17 | 160 |
| mixed | chain-18 | 160 |
| mixed | chain-19 | 160 |
| mixed | chain-20 | 160 |
| mixed | chain-21 | 160 |
| mixed | chain-22 | 160 |
| mixed | chain-23 | 160 |
| mixed | legacy:mixed | 64 |
| mixed | morse-chain | 160 |
| negative | hash-shaped | 160 |
| negative | legacy:negative | 16 |
| negative | password-hash | 160 |
| negative | random-bytes | 160 |
| plaintext | legacy:plaintext | 12 |
| plaintext | plaintext | 160 |
| repeated | ascii85 | 160 |
| repeated | base32 | 160 |
| repeated | base64 | 160 |
| repeated | base85 | 160 |
| repeated | binary | 160 |
| repeated | bzip2 | 160 |
| repeated | gzip | 160 |
| repeated | hex | 160 |
| repeated | hex-escapes | 160 |
| repeated | legacy:repeated | 32 |
| repeated | quoted-printable | 160 |
| repeated | unicode | 160 |
| repeated | url | 160 |
| repeated | xz | 160 |
| repeated | zlib | 160 |
| single | ascii85 | 160 |
| single | ascii85-adobe | 160 |
| single | atbash | 160 |
| single | base32 | 160 |
| single | base32-lower | 160 |
| single | base32-unpadded | 160 |
| single | base58 | 160 |
| single | base64 | 160 |
| single | base64-unpadded | 160 |
| single | base64-url | 160 |
| single | base64-wrapped | 160 |
| single | base85 | 160 |
| single | binary | 160 |
| single | binary-compact | 160 |
| single | bzip2 | 160 |
| single | caesar7 | 160 |
| single | decimal | 160 |
| single | decimal-comma | 160 |
| single | gzip | 160 |
| single | hex | 160 |
| single | hex-delimited | 160 |
| single | hex-escapes | 160 |
| single | hex-list | 160 |
| single | hex-prefix | 160 |
| single | hex-upper | 160 |
| single | html | 160 |
| single | html-hex | 160 |
| single | legacy:single | 156 |
| single | morse | 160 |
| single | octal | 160 |
| single | octal-escapes | 160 |
| single | octal-semicolon | 160 |
| single | quoted-printable | 160 |
| single | quoted-printable-soft | 160 |
| single | reverse | 160 |
| single | rot13 | 160 |
| single | rot47 | 160 |
| single | unicode | 160 |
| single | unicode-long | 160 |
| single | url | 160 |
| single | url-form | 160 |
| single | xor42 | 160 |
| single | xorFF | 160 |
| single | xz | 160 |
| single | zlib | 160 |
