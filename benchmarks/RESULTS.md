# Cryptid 1.0.0 evaluation

Run: 2026-09-27T18:41:52+00:00.
Runtime: CPython 3.12.14, Linux x86_64; 6 workers.
Fixture SHA-256: `fdc3762ad64282fce80dc71d5d342933dbe98f9f8922414895961147be7b7121`.
Application source/model SHA-256: `19b9ea98dabdfa208e3243460659904452382150f1b65ee18e99bb3946f22ee1`.
Cases evaluated: **17,040**, including **16,705 unique input/expected pairs**.

Exact original-byte equality and a successful status are required for positive top-1 recovery.
Negative controls pass only when the solver avoids declaring success. Top-5 presence does not prove recovery.
Seconds below are summed solver elapsed times; worker overlap makes them different from wall time.

| Group | Cases | Correct top-1 / rejection | In top-5 / rejection | Solver seconds |
| --- | ---: | ---: | ---: | ---: |
| advanced | 806 | 742 | 746 | 1552.29 |
| binary-output | 160 | 160 | 160 | 0.47 |
| heldout | 18 | 18 | 18 | 3.67 |
| key-sweep | 1856 | 1573 | 1844 | 311.53 |
| mixed | 4064 | 4038 | 4060 | 455.08 |
| negative | 496 | 496 | 496 | 152.36 |
| plaintext | 172 | 171 | 172 | 2.28 |
| repeated | 2272 | 2258 | 2272 | 116.42 |
| single | 7196 | 7153 | 7196 | 195.92 |

**Total correct: 16,609/17,040 (97.47%). Wall time: 465.85s.**

## Per-method breakdown

| Group | Method | Cases | Correct top-1 / rejection | In top-5 / rejection |
| --- | --- | ---: | ---: | ---: |
| advanced | columnar | 160 | 120 | 121 |
| advanced | legacy:advanced | 6 | 6 | 6 |
| advanced | rail-fence | 160 | 156 | 157 |
| advanced | repeating-xor | 160 | 154 | 155 |
| advanced | substitution | 160 | 150 | 150 |
| advanced | vigenere | 160 | 156 | 157 |
| binary-output | signature-only | 160 | 160 | 160 |
| heldout | legacy:heldout | 18 | 18 | 18 |
| key-sweep | affine | 624 | 623 | 623 |
| key-sweep | caesar | 208 | 182 | 208 |
| key-sweep | single-byte-xor | 1024 | 768 | 1013 |
| mixed | chain-00 | 160 | 159 | 160 |
| mixed | chain-01 | 160 | 158 | 159 |
| mixed | chain-02 | 160 | 159 | 160 |
| mixed | chain-03 | 160 | 158 | 158 |
| mixed | chain-04 | 160 | 159 | 160 |
| mixed | chain-05 | 160 | 159 | 160 |
| mixed | chain-06 | 160 | 159 | 160 |
| mixed | chain-07 | 160 | 159 | 160 |
| mixed | chain-08 | 160 | 159 | 160 |
| mixed | chain-09 | 160 | 159 | 160 |
| mixed | chain-10 | 160 | 159 | 160 |
| mixed | chain-11 | 160 | 159 | 160 |
| mixed | chain-12 | 160 | 159 | 160 |
| mixed | chain-13 | 160 | 159 | 160 |
| mixed | chain-14 | 160 | 159 | 160 |
| mixed | chain-15 | 160 | 159 | 159 |
| mixed | chain-16 | 160 | 159 | 160 |
| mixed | chain-17 | 160 | 159 | 160 |
| mixed | chain-18 | 160 | 159 | 160 |
| mixed | chain-19 | 160 | 159 | 160 |
| mixed | chain-20 | 160 | 159 | 160 |
| mixed | chain-21 | 160 | 159 | 160 |
| mixed | chain-22 | 160 | 159 | 160 |
| mixed | chain-23 | 160 | 159 | 160 |
| mixed | legacy:mixed | 64 | 64 | 64 |
| mixed | morse-chain | 160 | 160 | 160 |
| negative | hash-shaped | 160 | 160 | 160 |
| negative | legacy:negative | 16 | 16 | 16 |
| negative | password-hash | 160 | 160 | 160 |
| negative | random-bytes | 160 | 160 | 160 |
| plaintext | legacy:plaintext | 12 | 12 | 12 |
| plaintext | plaintext | 160 | 159 | 160 |
| repeated | ascii85 | 160 | 159 | 160 |
| repeated | base32 | 160 | 159 | 160 |
| repeated | base64 | 160 | 159 | 160 |
| repeated | base85 | 160 | 159 | 160 |
| repeated | binary | 160 | 159 | 160 |
| repeated | bzip2 | 160 | 159 | 160 |
| repeated | gzip | 160 | 159 | 160 |
| repeated | hex | 160 | 159 | 160 |
| repeated | hex-escapes | 160 | 159 | 160 |
| repeated | legacy:repeated | 32 | 32 | 32 |
| repeated | quoted-printable | 160 | 159 | 160 |
| repeated | unicode | 160 | 159 | 160 |
| repeated | url | 160 | 159 | 160 |
| repeated | xz | 160 | 159 | 160 |
| repeated | zlib | 160 | 159 | 160 |
| single | ascii85 | 160 | 159 | 160 |
| single | ascii85-adobe | 160 | 159 | 160 |
| single | atbash | 160 | 159 | 160 |
| single | base32 | 160 | 159 | 160 |
| single | base32-lower | 160 | 159 | 160 |
| single | base32-unpadded | 160 | 159 | 160 |
| single | base58 | 160 | 159 | 160 |
| single | base64 | 160 | 159 | 160 |
| single | base64-unpadded | 160 | 159 | 160 |
| single | base64-url | 160 | 159 | 160 |
| single | base64-wrapped | 160 | 159 | 160 |
| single | base85 | 160 | 159 | 160 |
| single | binary | 160 | 159 | 160 |
| single | binary-compact | 160 | 159 | 160 |
| single | bzip2 | 160 | 159 | 160 |
| single | caesar7 | 160 | 159 | 160 |
| single | decimal | 160 | 159 | 160 |
| single | decimal-comma | 160 | 159 | 160 |
| single | gzip | 160 | 159 | 160 |
| single | hex | 160 | 159 | 160 |
| single | hex-delimited | 160 | 159 | 160 |
| single | hex-escapes | 160 | 159 | 160 |
| single | hex-list | 160 | 159 | 160 |
| single | hex-prefix | 160 | 159 | 160 |
| single | hex-upper | 160 | 159 | 160 |
| single | html | 160 | 159 | 160 |
| single | html-hex | 160 | 159 | 160 |
| single | legacy:single | 156 | 156 | 156 |
| single | morse | 160 | 160 | 160 |
| single | octal | 160 | 159 | 160 |
| single | octal-escapes | 160 | 159 | 160 |
| single | octal-semicolon | 160 | 159 | 160 |
| single | quoted-printable | 160 | 159 | 160 |
| single | quoted-printable-soft | 160 | 159 | 160 |
| single | reverse | 160 | 159 | 160 |
| single | rot13 | 160 | 159 | 160 |
| single | rot47 | 160 | 159 | 160 |
| single | unicode | 160 | 159 | 160 |
| single | unicode-long | 160 | 159 | 160 |
| single | url | 160 | 159 | 160 |
| single | url-form | 160 | 159 | 160 |
| single | xor42 | 160 | 159 | 160 |
| single | xorFF | 160 | 159 | 160 |
| single | xz | 160 | 159 | 160 |
| single | zlib | 160 | 159 | 160 |

## Limits and provenance

These are development tests, not a blind external accuracy estimate. Training uses Gutenberg #11 and #1342;
evaluation prose comes from the separate #1661 snapshot. The model is not trained on this fixture.
Some variants intentionally produce identical bytes (for example Base64 alphabets when no special characters occur).
All methods, including unsuccessful statistical attacks, remain in the fixture and in the results.
A binary signature result identifies a header only; it does not validate the complete file.

Failures: **431**. Errors: **0**.

## Every failed case

| Case | Method | Status |
| --- | --- | --- |
| columnar-0002 | columnar | likely-plaintext |
| columnar-0008 | columnar | likely-plaintext |
| columnar-0010 | columnar | likely-plaintext |
| columnar-0012 | columnar | likely-plaintext |
| columnar-0015 | columnar | likely-plaintext |
| columnar-0020 | columnar | likely-plaintext |
| columnar-0022 | columnar | incomplete |
| columnar-0034 | columnar | incomplete |
| columnar-0036 | columnar | likely-plaintext |
| columnar-0046 | columnar | likely-plaintext |
| columnar-0048 | columnar | likely-plaintext |
| columnar-0057 | columnar | likely-plaintext |
| columnar-0060 | columnar | incomplete |
| columnar-0065 | columnar | likely-plaintext |
| columnar-0067 | columnar | likely-plaintext |
| columnar-0070 | columnar | likely-plaintext |
| columnar-0073 | columnar | likely-plaintext |
| columnar-0076 | columnar | likely-plaintext |
| columnar-0077 | columnar | likely-plaintext |
| columnar-0081 | columnar | likely-plaintext |
| columnar-0082 | columnar | likely-plaintext |
| columnar-0084 | columnar | likely-plaintext |
| columnar-0090 | columnar | likely-plaintext |
| columnar-0092 | columnar | likely-plaintext |
| columnar-0098 | columnar | likely-plaintext |
| columnar-0102 | columnar | likely-plaintext |
| columnar-0106 | columnar | likely-plaintext |
| columnar-0113 | columnar | likely-plaintext |
| columnar-0114 | columnar | likely-plaintext |
| columnar-0115 | columnar | likely-plaintext |
| columnar-0119 | columnar | likely-plaintext |
| columnar-0128 | columnar | likely-plaintext |
| columnar-0132 | columnar | likely-plaintext |
| columnar-0140 | columnar | likely-plaintext |
| columnar-0141 | columnar | likely-plaintext |
| columnar-0144 | columnar | likely-plaintext |
| columnar-0148 | columnar | likely-plaintext |
| columnar-0151 | columnar | likely-plaintext |
| columnar-0155 | columnar | likely-plaintext |
| columnar-0156 | columnar | likely-plaintext |
| rail-0034 | rail-fence | incomplete |
| rail-0043 | rail-fence | incomplete |
| rail-0066 | rail-fence | incomplete |
| rail-0075 | rail-fence | incomplete |
| repeating-xor-0017 | repeating-xor | likely-plaintext |
| repeating-xor-0023 | repeating-xor | incomplete |
| repeating-xor-0034 | repeating-xor | incomplete |
| repeating-xor-0041 | repeating-xor | likely-plaintext |
| repeating-xor-0055 | repeating-xor | likely-plaintext |
| repeating-xor-0158 | repeating-xor | likely-plaintext |
| substitution-0034 | substitution | incomplete |
| substitution-0040 | substitution | likely-plaintext |
| substitution-0042 | substitution | likely-plaintext |
| substitution-0047 | substitution | incomplete |
| substitution-0051 | substitution | likely-plaintext |
| substitution-0066 | substitution | likely-plaintext |
| substitution-0082 | substitution | likely-plaintext |
| substitution-0110 | substitution | incomplete |
| substitution-0123 | substitution | likely-plaintext |
| substitution-0130 | substitution | likely-plaintext |
| vigenere-0034 | vigenere | incomplete |
| vigenere-0046 | vigenere | likely-plaintext |
| vigenere-0076 | vigenere | incomplete |
| vigenere-0132 | vigenere | likely-plaintext |
| affine-key-09-07-1 | affine | already-plaintext |
| caesar-key-00-2 | caesar | incomplete |
| caesar-key-01-2 | caesar | incomplete |
| caesar-key-02-2 | caesar | incomplete |
| caesar-key-03-2 | caesar | incomplete |
| caesar-key-04-2 | caesar | incomplete |
| caesar-key-05-2 | caesar | incomplete |
| caesar-key-06-2 | caesar | incomplete |
| caesar-key-07-2 | caesar | incomplete |
| caesar-key-08-2 | caesar | incomplete |
| caesar-key-09-2 | caesar | incomplete |
| caesar-key-10-2 | caesar | incomplete |
| caesar-key-11-2 | caesar | incomplete |
| caesar-key-12-2 | caesar | incomplete |
| caesar-key-13-2 | caesar | incomplete |
| caesar-key-14-2 | caesar | incomplete |
| caesar-key-15-2 | caesar | incomplete |
| caesar-key-16-2 | caesar | incomplete |
| caesar-key-17-2 | caesar | incomplete |
| caesar-key-18-2 | caesar | incomplete |
| caesar-key-19-2 | caesar | incomplete |
| caesar-key-20-2 | caesar | incomplete |
| caesar-key-21-2 | caesar | incomplete |
| caesar-key-22-2 | caesar | incomplete |
| caesar-key-23-2 | caesar | incomplete |
| caesar-key-24-2 | caesar | incomplete |
| caesar-key-25-2 | caesar | incomplete |
| xor-key-000-2 | single-byte-xor | incomplete |
| xor-key-001-2 | single-byte-xor | incomplete |
| xor-key-002-2 | single-byte-xor | incomplete |
| xor-key-003-2 | single-byte-xor | incomplete |
| xor-key-004-2 | single-byte-xor | incomplete |
| xor-key-005-2 | single-byte-xor | incomplete |
| xor-key-006-2 | single-byte-xor | incomplete |
| xor-key-007-2 | single-byte-xor | incomplete |
| xor-key-008-2 | single-byte-xor | incomplete |
| xor-key-009-2 | single-byte-xor | incomplete |
| xor-key-010-2 | single-byte-xor | incomplete |
| xor-key-011-2 | single-byte-xor | incomplete |
| xor-key-012-2 | single-byte-xor | incomplete |
| xor-key-013-2 | single-byte-xor | incomplete |
| xor-key-014-2 | single-byte-xor | incomplete |
| xor-key-015-2 | single-byte-xor | incomplete |
| xor-key-016-2 | single-byte-xor | incomplete |
| xor-key-017-2 | single-byte-xor | incomplete |
| xor-key-018-2 | single-byte-xor | incomplete |
| xor-key-019-2 | single-byte-xor | incomplete |
| xor-key-020-2 | single-byte-xor | incomplete |
| xor-key-021-2 | single-byte-xor | incomplete |
| xor-key-022-2 | single-byte-xor | incomplete |
| xor-key-023-2 | single-byte-xor | incomplete |
| xor-key-024-2 | single-byte-xor | incomplete |
| xor-key-025-2 | single-byte-xor | incomplete |
| xor-key-026-2 | single-byte-xor | incomplete |
| xor-key-027-2 | single-byte-xor | incomplete |
| xor-key-028-2 | single-byte-xor | incomplete |
| xor-key-029-2 | single-byte-xor | incomplete |
| xor-key-030-2 | single-byte-xor | incomplete |
| xor-key-031-2 | single-byte-xor | incomplete |
| xor-key-032-2 | single-byte-xor | incomplete |
| xor-key-033-2 | single-byte-xor | incomplete |
| xor-key-034-2 | single-byte-xor | incomplete |
| xor-key-035-2 | single-byte-xor | incomplete |
| xor-key-036-2 | single-byte-xor | incomplete |
| xor-key-037-2 | single-byte-xor | incomplete |
| xor-key-038-2 | single-byte-xor | incomplete |
| xor-key-039-2 | single-byte-xor | incomplete |
| xor-key-040-2 | single-byte-xor | incomplete |
| xor-key-041-2 | single-byte-xor | incomplete |
| xor-key-042-2 | single-byte-xor | incomplete |
| xor-key-043-2 | single-byte-xor | incomplete |
| xor-key-044-2 | single-byte-xor | incomplete |
| xor-key-045-2 | single-byte-xor | incomplete |
| xor-key-046-2 | single-byte-xor | incomplete |
| xor-key-047-2 | single-byte-xor | incomplete |
| xor-key-048-2 | single-byte-xor | incomplete |
| xor-key-049-2 | single-byte-xor | incomplete |
| xor-key-050-2 | single-byte-xor | incomplete |
| xor-key-051-2 | single-byte-xor | incomplete |
| xor-key-052-2 | single-byte-xor | incomplete |
| xor-key-053-2 | single-byte-xor | incomplete |
| xor-key-054-2 | single-byte-xor | incomplete |
| xor-key-055-2 | single-byte-xor | incomplete |
| xor-key-056-2 | single-byte-xor | incomplete |
| xor-key-057-2 | single-byte-xor | incomplete |
| xor-key-058-2 | single-byte-xor | incomplete |
| xor-key-059-2 | single-byte-xor | incomplete |
| xor-key-060-2 | single-byte-xor | incomplete |
| xor-key-061-2 | single-byte-xor | incomplete |
| xor-key-062-2 | single-byte-xor | incomplete |
| xor-key-063-2 | single-byte-xor | incomplete |
| xor-key-064-2 | single-byte-xor | incomplete |
| xor-key-065-2 | single-byte-xor | incomplete |
| xor-key-066-2 | single-byte-xor | incomplete |
| xor-key-067-2 | single-byte-xor | incomplete |
| xor-key-068-2 | single-byte-xor | incomplete |
| xor-key-069-2 | single-byte-xor | incomplete |
| xor-key-070-2 | single-byte-xor | incomplete |
| xor-key-071-2 | single-byte-xor | incomplete |
| xor-key-072-2 | single-byte-xor | incomplete |
| xor-key-073-2 | single-byte-xor | incomplete |
| xor-key-074-2 | single-byte-xor | incomplete |
| xor-key-075-2 | single-byte-xor | incomplete |
| xor-key-076-2 | single-byte-xor | incomplete |
| xor-key-077-2 | single-byte-xor | incomplete |
| xor-key-078-2 | single-byte-xor | incomplete |
| xor-key-079-2 | single-byte-xor | incomplete |
| xor-key-080-2 | single-byte-xor | incomplete |
| xor-key-081-2 | single-byte-xor | incomplete |
| xor-key-082-2 | single-byte-xor | incomplete |
| xor-key-083-2 | single-byte-xor | incomplete |
| xor-key-084-2 | single-byte-xor | incomplete |
| xor-key-085-2 | single-byte-xor | incomplete |
| xor-key-086-2 | single-byte-xor | incomplete |
| xor-key-087-2 | single-byte-xor | incomplete |
| xor-key-088-2 | single-byte-xor | incomplete |
| xor-key-089-2 | single-byte-xor | incomplete |
| xor-key-090-2 | single-byte-xor | incomplete |
| xor-key-091-2 | single-byte-xor | incomplete |
| xor-key-092-2 | single-byte-xor | incomplete |
| xor-key-093-2 | single-byte-xor | incomplete |
| xor-key-094-2 | single-byte-xor | incomplete |
| xor-key-095-2 | single-byte-xor | incomplete |
| xor-key-096-2 | single-byte-xor | incomplete |
| xor-key-097-2 | single-byte-xor | incomplete |
| xor-key-098-2 | single-byte-xor | incomplete |
| xor-key-099-2 | single-byte-xor | incomplete |
| xor-key-100-2 | single-byte-xor | incomplete |
| xor-key-101-2 | single-byte-xor | incomplete |
| xor-key-102-2 | single-byte-xor | incomplete |
| xor-key-103-2 | single-byte-xor | incomplete |
| xor-key-104-2 | single-byte-xor | incomplete |
| xor-key-105-2 | single-byte-xor | incomplete |
| xor-key-106-2 | single-byte-xor | incomplete |
| xor-key-107-2 | single-byte-xor | incomplete |
| xor-key-108-2 | single-byte-xor | incomplete |
| xor-key-109-2 | single-byte-xor | incomplete |
| xor-key-110-2 | single-byte-xor | incomplete |
| xor-key-111-2 | single-byte-xor | incomplete |
| xor-key-112-2 | single-byte-xor | incomplete |
| xor-key-113-2 | single-byte-xor | incomplete |
| xor-key-114-2 | single-byte-xor | incomplete |
| xor-key-115-2 | single-byte-xor | incomplete |
| xor-key-116-2 | single-byte-xor | incomplete |
| xor-key-117-2 | single-byte-xor | incomplete |
| xor-key-118-2 | single-byte-xor | incomplete |
| xor-key-119-2 | single-byte-xor | incomplete |
| xor-key-120-2 | single-byte-xor | incomplete |
| xor-key-121-2 | single-byte-xor | incomplete |
| xor-key-122-2 | single-byte-xor | incomplete |
| xor-key-123-2 | single-byte-xor | incomplete |
| xor-key-124-2 | single-byte-xor | incomplete |
| xor-key-125-2 | single-byte-xor | incomplete |
| xor-key-126-2 | single-byte-xor | incomplete |
| xor-key-127-2 | single-byte-xor | incomplete |
| xor-key-128-2 | single-byte-xor | incomplete |
| xor-key-129-2 | single-byte-xor | incomplete |
| xor-key-130-2 | single-byte-xor | incomplete |
| xor-key-131-2 | single-byte-xor | incomplete |
| xor-key-132-2 | single-byte-xor | incomplete |
| xor-key-133-2 | single-byte-xor | incomplete |
| xor-key-134-2 | single-byte-xor | incomplete |
| xor-key-135-2 | single-byte-xor | incomplete |
| xor-key-136-2 | single-byte-xor | incomplete |
| xor-key-137-2 | single-byte-xor | incomplete |
| xor-key-138-2 | single-byte-xor | incomplete |
| xor-key-139-2 | single-byte-xor | incomplete |
| xor-key-140-2 | single-byte-xor | incomplete |
| xor-key-141-2 | single-byte-xor | incomplete |
| xor-key-142-2 | single-byte-xor | incomplete |
| xor-key-143-2 | single-byte-xor | incomplete |
| xor-key-144-2 | single-byte-xor | incomplete |
| xor-key-145-2 | single-byte-xor | incomplete |
| xor-key-146-2 | single-byte-xor | incomplete |
| xor-key-147-2 | single-byte-xor | incomplete |
| xor-key-148-2 | single-byte-xor | incomplete |
| xor-key-149-2 | single-byte-xor | incomplete |
| xor-key-150-2 | single-byte-xor | incomplete |
| xor-key-151-2 | single-byte-xor | incomplete |
| xor-key-152-2 | single-byte-xor | incomplete |
| xor-key-153-2 | single-byte-xor | incomplete |
| xor-key-154-2 | single-byte-xor | incomplete |
| xor-key-155-2 | single-byte-xor | incomplete |
| xor-key-156-2 | single-byte-xor | incomplete |
| xor-key-157-2 | single-byte-xor | incomplete |
| xor-key-158-2 | single-byte-xor | incomplete |
| xor-key-159-2 | single-byte-xor | incomplete |
| xor-key-160-2 | single-byte-xor | incomplete |
| xor-key-161-2 | single-byte-xor | incomplete |
| xor-key-162-2 | single-byte-xor | incomplete |
| xor-key-163-2 | single-byte-xor | incomplete |
| xor-key-164-2 | single-byte-xor | incomplete |
| xor-key-165-2 | single-byte-xor | incomplete |
| xor-key-166-2 | single-byte-xor | incomplete |
| xor-key-167-2 | single-byte-xor | incomplete |
| xor-key-168-2 | single-byte-xor | incomplete |
| xor-key-169-2 | single-byte-xor | incomplete |
| xor-key-170-2 | single-byte-xor | incomplete |
| xor-key-171-2 | single-byte-xor | incomplete |
| xor-key-172-2 | single-byte-xor | incomplete |
| xor-key-173-2 | single-byte-xor | incomplete |
| xor-key-174-2 | single-byte-xor | incomplete |
| xor-key-175-2 | single-byte-xor | incomplete |
| xor-key-176-2 | single-byte-xor | incomplete |
| xor-key-177-2 | single-byte-xor | incomplete |
| xor-key-178-2 | single-byte-xor | incomplete |
| xor-key-179-2 | single-byte-xor | incomplete |
| xor-key-180-2 | single-byte-xor | incomplete |
| xor-key-181-2 | single-byte-xor | incomplete |
| xor-key-182-2 | single-byte-xor | incomplete |
| xor-key-183-2 | single-byte-xor | incomplete |
| xor-key-184-2 | single-byte-xor | incomplete |
| xor-key-185-2 | single-byte-xor | incomplete |
| xor-key-186-2 | single-byte-xor | incomplete |
| xor-key-187-2 | single-byte-xor | incomplete |
| xor-key-188-2 | single-byte-xor | incomplete |
| xor-key-189-2 | single-byte-xor | incomplete |
| xor-key-190-2 | single-byte-xor | incomplete |
| xor-key-191-2 | single-byte-xor | incomplete |
| xor-key-192-2 | single-byte-xor | incomplete |
| xor-key-193-2 | single-byte-xor | incomplete |
| xor-key-194-2 | single-byte-xor | incomplete |
| xor-key-195-2 | single-byte-xor | incomplete |
| xor-key-196-2 | single-byte-xor | incomplete |
| xor-key-197-2 | single-byte-xor | incomplete |
| xor-key-198-2 | single-byte-xor | incomplete |
| xor-key-199-2 | single-byte-xor | incomplete |
| xor-key-200-2 | single-byte-xor | incomplete |
| xor-key-201-2 | single-byte-xor | incomplete |
| xor-key-202-2 | single-byte-xor | incomplete |
| xor-key-203-2 | single-byte-xor | incomplete |
| xor-key-204-2 | single-byte-xor | incomplete |
| xor-key-205-2 | single-byte-xor | incomplete |
| xor-key-206-2 | single-byte-xor | incomplete |
| xor-key-207-2 | single-byte-xor | incomplete |
| xor-key-208-2 | single-byte-xor | incomplete |
| xor-key-209-2 | single-byte-xor | incomplete |
| xor-key-210-2 | single-byte-xor | incomplete |
| xor-key-211-2 | single-byte-xor | incomplete |
| xor-key-212-2 | single-byte-xor | incomplete |
| xor-key-213-2 | single-byte-xor | incomplete |
| xor-key-214-2 | single-byte-xor | incomplete |
| xor-key-215-2 | single-byte-xor | incomplete |
| xor-key-216-2 | single-byte-xor | incomplete |
| xor-key-217-2 | single-byte-xor | incomplete |
| xor-key-218-2 | single-byte-xor | incomplete |
| xor-key-219-2 | single-byte-xor | incomplete |
| xor-key-220-2 | single-byte-xor | incomplete |
| xor-key-221-2 | single-byte-xor | incomplete |
| xor-key-222-2 | single-byte-xor | incomplete |
| xor-key-223-2 | single-byte-xor | incomplete |
| xor-key-224-2 | single-byte-xor | incomplete |
| xor-key-225-2 | single-byte-xor | incomplete |
| xor-key-226-2 | single-byte-xor | incomplete |
| xor-key-227-2 | single-byte-xor | incomplete |
| xor-key-228-2 | single-byte-xor | incomplete |
| xor-key-229-2 | single-byte-xor | incomplete |
| xor-key-230-2 | single-byte-xor | incomplete |
| xor-key-231-2 | single-byte-xor | incomplete |
| xor-key-232-2 | single-byte-xor | incomplete |
| xor-key-233-2 | single-byte-xor | incomplete |
| xor-key-234-2 | single-byte-xor | incomplete |
| xor-key-235-2 | single-byte-xor | incomplete |
| xor-key-236-2 | single-byte-xor | incomplete |
| xor-key-237-2 | single-byte-xor | incomplete |
| xor-key-238-2 | single-byte-xor | incomplete |
| xor-key-239-2 | single-byte-xor | incomplete |
| xor-key-240-2 | single-byte-xor | incomplete |
| xor-key-241-2 | single-byte-xor | incomplete |
| xor-key-242-2 | single-byte-xor | incomplete |
| xor-key-243-2 | single-byte-xor | incomplete |
| xor-key-244-2 | single-byte-xor | incomplete |
| xor-key-245-2 | single-byte-xor | incomplete |
| xor-key-246-2 | single-byte-xor | incomplete |
| xor-key-247-2 | single-byte-xor | incomplete |
| xor-key-248-2 | single-byte-xor | incomplete |
| xor-key-249-2 | single-byte-xor | incomplete |
| xor-key-250-2 | single-byte-xor | incomplete |
| xor-key-251-2 | single-byte-xor | incomplete |
| xor-key-252-2 | single-byte-xor | incomplete |
| xor-key-253-2 | single-byte-xor | incomplete |
| xor-key-254-2 | single-byte-xor | incomplete |
| xor-key-255-2 | single-byte-xor | incomplete |
| chain-00-0002 | chain-00 | incomplete |
| chain-01-0002 | chain-01 | incomplete |
| chain-01-0122 | chain-01 | incomplete |
| chain-02-0002 | chain-02 | incomplete |
| chain-03-0002 | chain-03 | incomplete |
| chain-03-0150 | chain-03 | incomplete |
| chain-04-0002 | chain-04 | incomplete |
| chain-05-0002 | chain-05 | incomplete |
| chain-06-0002 | chain-06 | incomplete |
| chain-07-0002 | chain-07 | incomplete |
| chain-08-0002 | chain-08 | incomplete |
| chain-09-0002 | chain-09 | incomplete |
| chain-10-0002 | chain-10 | incomplete |
| chain-11-0002 | chain-11 | incomplete |
| chain-12-0002 | chain-12 | incomplete |
| chain-13-0002 | chain-13 | incomplete |
| chain-14-0002 | chain-14 | incomplete |
| chain-15-0002 | chain-15 | incomplete |
| chain-16-0002 | chain-16 | incomplete |
| chain-17-0002 | chain-17 | incomplete |
| chain-18-0002 | chain-18 | incomplete |
| chain-19-0002 | chain-19 | incomplete |
| chain-20-0002 | chain-20 | incomplete |
| chain-21-0002 | chain-21 | incomplete |
| chain-22-0002 | chain-22 | incomplete |
| chain-23-0002 | chain-23 | incomplete |
| new-plain-2 | plaintext | incomplete |
| repeat-ascii85-0002 | ascii85 | incomplete |
| repeat-base32-0002 | base32 | incomplete |
| repeat-base64-0002 | base64 | incomplete |
| repeat-base85-0002 | base85 | incomplete |
| repeat-binary-0002 | binary | incomplete |
| repeat-bzip2-0002 | bzip2 | incomplete |
| repeat-gzip-0002 | gzip | incomplete |
| repeat-hex-0002 | hex | incomplete |
| repeat-hex-escapes-0002 | hex-escapes | incomplete |
| repeat-quoted-printable-0002 | quoted-printable | incomplete |
| repeat-unicode-0002 | unicode | incomplete |
| repeat-url-0002 | url | incomplete |
| repeat-xz-0002 | xz | incomplete |
| repeat-zlib-0002 | zlib | incomplete |
| single-ascii85-0002 | ascii85 | incomplete |
| single-ascii85-adobe-0002 | ascii85-adobe | incomplete |
| single-atbash-0002 | atbash | incomplete |
| single-base32-0002 | base32 | incomplete |
| single-base32-lower-0002 | base32-lower | incomplete |
| single-base32-unpadded-0002 | base32-unpadded | incomplete |
| single-base58-0002 | base58 | incomplete |
| single-base64-0002 | base64 | incomplete |
| single-base64-unpadded-0002 | base64-unpadded | incomplete |
| single-base64-url-0002 | base64-url | incomplete |
| single-base64-wrapped-0002 | base64-wrapped | incomplete |
| single-base85-0002 | base85 | incomplete |
| single-binary-0002 | binary | incomplete |
| single-binary-compact-0002 | binary-compact | incomplete |
| single-bzip2-0002 | bzip2 | incomplete |
| single-caesar7-0002 | caesar7 | incomplete |
| single-decimal-0002 | decimal | incomplete |
| single-decimal-comma-0002 | decimal-comma | incomplete |
| single-gzip-0002 | gzip | incomplete |
| single-hex-0002 | hex | incomplete |
| single-hex-delimited-0002 | hex-delimited | incomplete |
| single-hex-escapes-0002 | hex-escapes | incomplete |
| single-hex-list-0002 | hex-list | incomplete |
| single-hex-prefix-0002 | hex-prefix | incomplete |
| single-hex-upper-0002 | hex-upper | incomplete |
| single-html-0002 | html | incomplete |
| single-html-hex-0002 | html-hex | incomplete |
| single-octal-0002 | octal | incomplete |
| single-octal-escapes-0002 | octal-escapes | incomplete |
| single-octal-semicolon-0002 | octal-semicolon | incomplete |
| single-quoted-printable-0002 | quoted-printable | incomplete |
| single-quoted-printable-soft-0002 | quoted-printable-soft | incomplete |
| single-reverse-0002 | reverse | incomplete |
| single-rot13-0002 | rot13 | incomplete |
| single-rot47-0002 | rot47 | incomplete |
| single-unicode-0002 | unicode | incomplete |
| single-unicode-long-0002 | unicode-long | incomplete |
| single-url-0002 | url | incomplete |
| single-url-form-0002 | url-form | incomplete |
| single-xor42-0002 | xor42 | incomplete |
| single-xorFF-0002 | xorFF | incomplete |
| single-xz-0002 | xz | incomplete |
| single-zlib-0002 | zlib | incomplete |
