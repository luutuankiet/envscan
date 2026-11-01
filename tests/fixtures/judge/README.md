# Recorded verdicts

`recorded-p.json` holds one vendor verdict per broad-fixture candidate: `file`, `line`, `value`
and the recorded `p` (model `jev-1.14.0`). The loopback stub in `tests/judge.rs` replays it.

It was recorded on the fixture that `../broad/` was copied from, so the two tokens that fixture
replaced are replaced here too, and home paths and email at-signs use the same placeholders as
`../broad/`. All 92 rows match the 92 candidates in `../broad/expected.jsonl` by file, line and
value. 58 rows have p above 0.3; two sit at exactly 0.300 and are not kept.
