# Broad extractor fixture

Invented text with planted identifiers and public decoys. The two tokens that matched real
accounts in the fixture this one is copied from were replaced with tokens checked free on
GitHub and DNS. Home paths stay `<HOME>` and `<USERS>`, and an email's at-sign stays `<AT>`, here and in the golden;
tests expand them, so this repo holds no literal home path or email.

| file | what it is |
|---|---|
| `make_fixture.py` | writes `fixture/` and `answer-key.json` |
| `golden.py` | the Python reference `extract()`; writes `expected.jsonl` and `fuzz.sums` |
| `expected.jsonl` | ordered `(value, shape)` per flagged fixture line |
| `fuzz.sums` | a running FNV-1a sum every 1,000 of 200,000 seeded ASCII lines, so the golden needs no large file |

Regenerate, from this folder:

```sh
python3 -I make_fixture.py && python3 -I golden.py
```

Ignore and `.env` cases are built in a temp dir by the tests.
