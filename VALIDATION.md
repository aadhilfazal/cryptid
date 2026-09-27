# Local release validation - Cryptid 1.0.0

Validated on 2026-09-27 using Linux x86_64 and CPython 3.12.14.
The full benchmark used 6 CPU workers. No GitHub CI or remote publication is claimed.

| Check | Measured result |
| --- | --- |
| Regression suite | 49 test methods passed, including 995 parameterized subcases. |
| Core benchmark | All 15 release-critical cases passed. |
| Full evaluation | 16,609 / 17,040 correct outcomes (97.47%). |
| Positive exact-byte recovery | 16,113 / 16,544; this includes 160 binary-signature cases. |
| Negative controls | 496 / 496 correctly avoided a success claim. |
| Crashes during full evaluation | 0. |
| Unsuccessful evaluation cases | 431 retained and listed, including 51 incorrect successful selections. |
| Unique fixture input/expected pairs | 16,705; equivalent encoding variants account for overlaps. |
| Fixture regeneration | Rebuilt offline and byte-identical to the supplied fixture. |
| Offline installation | Installed and reinstalled into an isolated prefix containing a space and apostrophe. |
| Installed command | Correct version/watermark and all 3 examples passed outside the source folder. |
| Python package | Wheel built offline; metadata, language model and all runtime files verified. |
| Source review | Python sources parse; first-release branding is consistent across code and documentation. |

Full evaluation wall time was 465.85 seconds on this runtime. Performance and
budget-limited outcomes may vary with CPU, Python version and simultaneous load.

The model contains 7,788 word entries and 37,083 quadgram entries. It was not
retrained on the new evaluation cases. Full per-method results and every failed
case are in `benchmarks/RESULTS.md`; `benchmarks/results.tsv` has one record for
every evaluation case, including routes, statuses and output hashes.

## Practical limits found by the larger test

Name-heavy passages and a contents list can be decoded to the original bytes
without reaching the English confidence threshold. Many key-sweep failures use
that same difficult title list. The result can therefore be incomplete even
when a correct candidate is retained; top-5 presence is measured separately.

Statistical attacks can also choose readable but incorrect text. Columnar
transposition is particularly sensitive to punctuation, boundary shifts and
short passages (120/160 exact results in its expanded group). A known flag
wrapper is not server validation; some Affine keys map one recognised prefix
to another. All these failures remain visible in the reported totals.

The overall percentage applies to this development fixture only, and combines
positive recovery with correctly rejected negative controls. It is not a claim
of universal decoding accuracy or unlimited layer depth.
