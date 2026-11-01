#!/usr/bin/env python3
"""Write expected.jsonl and fuzz.sums from the Python extract(). See README.md.

The extract() block is the reference the Rust port is held to: change neither side alone.
"""
import json, os, re

HERE = os.path.dirname(os.path.abspath(__file__))
HOME, USERS = "/" + "home", "/" + "Users"

# ---- reference extractor ----
SHAPES = [  # order = priority; a later span overlapping an earlier one is dropped
    ("bucket", r"\b(?:gs|s3)://[A-Za-z0-9._-]+"),
    ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ("url-host", r"(?<=://)[A-Za-z0-9.-]+"),
    ("gh-repo", r"(?<=github\.com/)[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"),
    ("home-path", r"(?:/home|/Users)/[^\s\"'`:,)]+"),
    ("ip", r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?![\d])"),
    ("filename", r"[A-Za-z0-9_.-]+\.(?:csv|xlsx|pdf|txt|parquet)\b"),
    ("hostname", r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\.[a-z]{2,}\b|\b[a-z0-9-]+\.(?:internal|lan|local|corp)\b"),
    ("owner-repo", r"(?<![/\w.-])[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9_.-]*(?![/\w])"),
    ("account-id", r"\b\d{12}\b"),
    ("handle", r"(?<![\w.])@[a-z][a-z0-9_-]+"),
    ("slug", r"\b[a-z][a-z0-9]*(?:-[a-z0-9]+){1,}\b"),
    ("proper-noun", r"\b[A-Z][a-z]{3,}(?: [A-Z][a-z]{3,})*\b"),
]
COMMON_CAPS = set("""Session Context Client What Open Questions Decisions Should Probably Retried Exported Ask Upgrade
Keep Nothing Ping Move Delete Confirm Notes Steps Opened Compared Checked Handoff Dashboard Their Landing Repo
Remember Another Look Compare Measure Write Version Public Scratch Old Prod Raw The This That Ran Retry Use
Weekly Monday Thursday Timezone Ping Try Remember Moved Done Starting""".split())


def extract(line):
    taken, out = [], []
    for kind, rx in SHAPES:
        for m in re.finditer(rx, line):
            s, e = m.span()
            if any(s < te and ts < e for ts, te in taken):
                continue
            v = m.group(0).rstrip(".")
            if kind == "proper-noun" and (v in COMMON_CAPS or s <= 2):
                continue
            if kind == "ip" and v.count(".") != 3:
                continue
            taken.append((s, e)); out.append({"value": v, "shape": kind})
    return out
# ---- end of reference extractor ----


def pairs(line):
    """Empty values are dropped by the spec, after they have taken their span."""
    return [[c["value"], c["shape"]] for c in extract(line) if c["value"]]


FRAGMENTS = ["gs://", "s3://", "://", "http://", "github.com/", HOME + "/", USERS + "/", "@", ".", "-", "_", "/",
             " ", ".csv", ".txt", ".pdf", ".lan", ".internal", ".corp", ".local", ".com", "10.20.30.41", "1.2.3",
             "/24", "123456789012", "Quill", "Quill Feather", "Session", "The", "foo", "bar", "a-b", "x/y", "é"[:0]]
FRAGMENTS = [f for f in FRAGMENTS if f]
FUZZ_LINES, FUZZ_BLOCK = 200_000, 1000


class Lcg:
    """The same generator is in tests/extract.rs, so the lines need no file."""
    def __init__(self):
        self.state = 0x2545F4914F6CDD1D

    def next(self, bound):
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & (2**64 - 1)
        return (self.state >> 33) % bound


def fuzz_line(rng):
    out = []
    for _ in range(rng.next(12) + 1):
        if rng.next(3) == 0:
            # Every ASCII character but the line separator.
            run = rng.next(6) + 1
            for _ in range(run):
                c = rng.next(127)
                out.append(" " if c == 10 else chr(c))
        else:
            out.append(FRAGMENTS[rng.next(len(FRAGMENTS))])
    line = "".join(out)
    return line[:-1] if line.endswith("\r") else line


def fnv(data, h=0xcbf29ce484222325):
    for b in data:
        h = ((h ^ b) * 0x100000001b3) & (2**64 - 1)
    return h


def fold(line_pairs, h):
    for value, shape in line_pairs:
        h = fnv(value.encode() + b"\0" + shape.encode() + b"\0", h)
    return fnv(b"\n", h)


def main():
    with open(os.path.join(HERE, "expected.jsonl"), "w") as f:
        root = os.path.join(HERE, "fixture")
        for d, _, names in sorted(os.walk(root)):
            for name in sorted(names):
                path = os.path.join(d, name)
                rel = os.path.relpath(path, root)
                text = open(path, newline="").read().replace("<HOME>", HOME).replace("<USERS>", USERS).replace("<AT>", "@")
                for n, line in enumerate(text.split("\n"), 1):
                    line = line[:-1] if line.endswith("\r") else line
                    found = pairs(line)
                    if found:
                        for pair in found:
                            pair[0] = pair[0].replace(HOME + "/", "<HOME>/").replace(USERS + "/", "<USERS>/")
                            if pair[1] == "email":
                                pair[0] = pair[0].replace("@", "<AT>")
                        f.write(json.dumps({"file": rel, "line": n, "found": found}) + "\n")
    rng, h, candidates = Lcg(), 0xcbf29ce484222325, 0
    with open(os.path.join(HERE, "fuzz.sums"), "w") as f:
        for i in range(1, FUZZ_LINES + 1):
            found = pairs(fuzz_line(rng))
            candidates += len(found)
            h = fold(found, h)
            if i % FUZZ_BLOCK == 0:
                f.write(f"{h:016x}\n")
    print(f"fuzz lines={FUZZ_LINES} candidates={candidates}")


if __name__ == "__main__":
    main()
