# Contributing

Run the unit suite and core benchmark before opening a pull request. For a new
decoder, add an independent known-answer vector, a nested challenge, and a
negative/malformed-input test. Preserve arbitrary byte values and whitespace.

Decoders must return actual `Transform` objects. Never execute input, silently
repair padding bits, discard bytes, or claim a guess is verified plaintext.
Keep heavy attacks bounded and document assumptions and searched key ranges.

Do not train the language model on the held-out evaluation plaintexts or remove
failing cases to inflate the result. Record accuracy by group and list failures.
Performance reports must identify the dataset and runtime used.

