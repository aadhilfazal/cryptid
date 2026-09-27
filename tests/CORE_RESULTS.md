# Cryptid 1.0.0 evaluation

Run: 2026-09-27T18:35:18+00:00.
Runtime: CPython 3.12.14, Linux x86_64; 1 workers.
Fixture SHA-256: `fdc3762ad64282fce80dc71d5d342933dbe98f9f8922414895961147be7b7121`.
Application source/model SHA-256: `19b9ea98dabdfa208e3243460659904452382150f1b65ee18e99bb3946f22ee1`.
Cases evaluated: **15**, including **15 unique input/expected pairs**.

Exact original-byte equality and a successful status are required for positive top-1 recovery.
Negative controls pass only when the solver avoids declaring success. Top-5 presence does not prove recovery.
Seconds below are summed solver elapsed times; worker overlap makes them different from wall time.

| Group | Cases | Correct top-1 / rejection | In top-5 / rejection | Solver seconds |
| --- | ---: | ---: | ---: | ---: |
| advanced | 6 | 6 | 6 | 10.18 |
| mixed | 6 | 6 | 6 | 0.83 |
| repeated | 3 | 3 | 3 | 0.23 |

**Total correct: 15/15 (100.00%). Wall time: 11.24s.**

## Per-method breakdown

| Group | Method | Cases | Correct top-1 / rejection | In top-5 / rejection |
| --- | --- | ---: | ---: | ---: |
| advanced | legacy:advanced | 6 | 6 | 6 |
| mixed | legacy:mixed | 6 | 6 | 6 |
| repeated | legacy:repeated | 3 | 3 | 3 |

## Limits and provenance

These are development tests, not a blind external accuracy estimate. Training uses Gutenberg #11 and #1342;
evaluation prose comes from the separate #1661 snapshot. The model is not trained on this fixture.
Some variants intentionally produce identical bytes (for example Base64 alphabets when no special characters occur).
All methods, including unsuccessful statistical attacks, remain in the fixture and in the results.
A binary signature result identifies a header only; it does not validate the complete file.

Failures: **0**. Errors: **0**.

