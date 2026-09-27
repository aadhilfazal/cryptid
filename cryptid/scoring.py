"""Offline evidence and English scoring. Scores are ranks, NOT probabilities."""
from __future__ import annotations

import ast
from collections import Counter
from functools import lru_cache
import gzip
import json
import math
from pathlib import Path
import re

from .models import Assessment

ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
FLAG = re.compile(r"(?:flag|ctf|htb|kap|picoctf|thm)\{[^{}\r\n]{1,4096}\}", re.I)
GENERIC_FLAG = re.compile(r"[A-Za-z][A-Za-z0-9_]{1,24}\{[^{}\r\n]{2,2048}\}")
FREQ = [8.17,1.49,2.78,4.25,12.70,2.23,2.02,6.09,6.97,0.15,0.77,
        4.03,2.41,6.75,7.51,1.93,0.10,5.99,6.33,9.06,2.76,0.98,2.36,0.15,1.97,0.07]
MAGIC = [(b"\x89PNG\r\n\x1a\n", "PNG image"), (b"\xff\xd8\xff", "JPEG image"),
         (b"GIF87a", "GIF image"), (b"GIF89a", "GIF image"), (b"%PDF-", "PDF"),
         (b"\x7fELF", "ELF executable"), (b"SQLite format 3\0", "SQLite database"),
         (b"PK\x03\x04", "ZIP archive"), (b"PK\x05\x06", "empty ZIP archive")]


@lru_cache(maxsize=1)
def language_model():
    path = Path(__file__).with_name("data") / "english.json.gz"
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        model = json.load(fh)
    words = model["words"]
    counts = model["quadgrams"]
    total = sum(counts.values())
    logs = {q: math.log10(n / total) for q, n in counts.items()}
    return words, logs, math.log10(0.15 / total)


def preview(data: bytes, limit=120) -> str:
    """Escape controls, including terminal escape sequences, in human output."""
    try:
        s = data.decode("utf-8")
        return ascii(s[:limit]) + (" …" if len(s) > limit else "")
    except UnicodeDecodeError:
        return f"<{len(data)} bytes: {data[:32].hex()}{'…' if len(data)>32 else ''}>"


def printable(data: bytes) -> float:
    return sum(32 <= b < 127 or b in (9,10,13) for b in data) / max(1,len(data))


def quad_score(text: str) -> float:
    _, logs, floor = language_model()
    s = re.sub("[^a-z]", "", text.lower())
    if len(s) < 4:
        return floor
    return sum(logs.get(s[i:i+4], floor) for i in range(len(s)-3)) / (len(s)-3)


def column_score(data: bytes) -> float:
    """Log likelihood for transposed XOR columns (spacing no longer survives)."""
    score = 0.0
    for b in data:
        if b == 32:
            score += -1.7
        elif 65 <= b <= 90 or 97 <= b <= 122:
            score += math.log(max(0.001, FREQ[(b | 32)-97] * 0.0075))
            if 65 <= b <= 90:
                score -= 1.8
        elif b in b"\n\r\t.,'\"!?;:-()0123456789_{}":
            score += -5.4
        elif 32 <= b < 127:
            score += -8.5
        else:
            score += -15.0
    return score / max(1,len(data))


def assess(data: bytes) -> Assessment:
    # Bound scoring cost; preserve complete bytes in candidates and output.
    sample = data if len(data) <= 6144 else data[:4096] + b"\n" + data[-2048:]
    return _assess_sample(sample)


@lru_cache(maxsize=6000)
def _assess_sample(data: bytes) -> Assessment:
    for signature, label in MAGIC:
        if data.startswith(signature):
            return Assessment(0.94, "binary", f"Recognised {label} signature; not plaintext")
    if not data:
        return Assessment(0.0, "unknown", "Empty output")
    if printable(data) < 0.97:
        return Assessment(0.02, "unknown", "Contains binary/control bytes")
    if any((b<32 and b not in (9,10,13)) or b==127 for b in data):
        return Assessment(0.02,"unknown","Contains control bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return Assessment(0.02,"unknown","Not valid UTF-8 text")
    s = text.strip()
    if not s:
        return Assessment(0.05, "unknown", "Whitespace only")
    match = FLAG.fullmatch(s)
    if match:
        body = s[s.index("{")+1:-1]
        # Several Affine keys can map one known wrapper to another. Readable
        # body text breaks ties without requiring English inside every flag.
        body_score = assess(body.encode("utf-8")).score
        return Assessment(0.99 + 0.008 * body_score, "flag", "Recognised CTF flag wrapper; contents are preserved")
    if FLAG.search(s):
        context = FLAG.sub(" ", s).strip()
        if not context or assess(context.encode("utf-8")).score >= 0.76:
            return Assessment(0.975, "flag", "Recognised CTF flag inside readable text")
    if s[:1] in "[{" and s[-1:] in "]}":
        try:
            parsed = json.loads(s)
            if isinstance(parsed, (dict,list)):
                return Assessment(0.97, "structured", "Valid structured text")
        except (ValueError, RecursionError):
            pass
    if re.fullmatch(r"https?://[A-Za-z0-9.-]+(?:[/:?][^\s]*)?", s):
        return Assessment(0.94, "structured", "Readable URL")
    if s.startswith("<") and s.endswith(">") and len(s)<12000:
        import xml.etree.ElementTree as ET
        try:
            ET.fromstring(s)
            return Assessment(0.94, "structured", "Well-formed XML/markup")
        except (ET.ParseError,ValueError):
            pass
    if re.match(r"(?:print\s*\(|def\s+|class\s+|import\s+|from\s+\w+\s+import\s+)",s) and len(s) < 12000:
        try:
            tree = ast.parse(s)
            if any(isinstance(n, (ast.Call,ast.Assign,ast.FunctionDef,ast.Import,ast.ImportFrom))
                   for n in ast.walk(tree)):
                return Assessment(0.93, "structured", "Syntactically valid Python code (not executed)")
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            pass
    words, _, _ = language_model()
    tokens = re.findall(r"[a-z]+", s.lower())
    total = sum(len(w) for w in tokens)
    if not total:
        return Assessment(0.12, "unknown", "No English letters")
    useful = [w for w in tokens if len(w) >= 2 or w in ("a", "i")]
    def known(w):
        if w in words:
            return True
        for ending in ("s","es","ed","ing","ly"):
            if len(w)>len(ending)+2 and w.endswith(ending):
                stem=w[:-len(ending)]
                if stem in words or stem+"e" in words:
                    return True
        return False
    covered = sum(len(w) for w in useful if known(w))
    coverage = covered / total
    q = quad_score(s)
    qnorm = max(0.0, min(1.0, (q + 6.8) / 2.5))
    # A small common-word vocabulary alone overfits. Combine corpus coverage,
    # character sequences, enough observations, and reasonable word boundaries.
    score = 0.10 + 0.60 * coverage + 0.26 * qnorm
    # Long coherent passages can contain names absent from the small dictionary.
    # Additional character-sequence evidence grows with text length.
    if coverage >= 0.65:
        score += 0.06 * min(1.0, total / 200) * qnorm
    if len(tokens) >= 3 and coverage > 0.65:
        score += 0.06
    if len(tokens) == 1:
        score -= 0.06
    if total < 6:
        score = min(score, 0.76)
    upper = sum(c.isupper() for c in s) / total
    if upper > 0.7 and total > 8:
        score -= 0.035
    nontext = sum(not(c.isalnum() or c.isspace() or c in ".,!?':;\"-_()/{}[]") for c in s)
    score -= min(0.20, nontext / max(len(s),1))
    density=total/max(1,len(s))
    if density<0.55:
        score *= density/0.55
    if (len(tokens)>=4 and len(set(tokens))<3) or (len(tokens)>=3 and len(set(tokens))==1):
        score=min(score,0.60)
    if re.search(r"(.)\1{5,}", s):
        score -= 0.18
    if GENERIC_FLAG.fullmatch(s):
        score = max(score, 0.78)
    score = max(0.02, min(0.96, score))
    return Assessment(score, "english" if score >= 0.76 else "unknown",
                      f"English word coverage {coverage:.0%}; character-sequence score {q:.2f}")
