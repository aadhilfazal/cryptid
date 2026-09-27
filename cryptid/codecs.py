"""Strict reversible formats. Untrusted data is never executed or extracted."""
from __future__ import annotations

import base64
import binascii
import bz2
import html
import lzma
import re
import urllib.parse
import zlib

from .models import Transform

MAX_OUTPUT = 4 * 1024 * 1024
B58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MORSE = dict(zip(
    ".- -... -.-. -.. . ..-. --. .... .. .--- -.- .-.. -- -. --- .--. --.- .-. ... - ..- ...- .-- -..- -.-- --.. ----- .---- ..--- ...-- ....- ..... -.... --... ---.. ----. .-.-.- --..-- ..--.. -..-. -....- .--.-. ---... -...-".split(),
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,?/-@:=",
))


def _zlib_header(data: bytes) -> bool:
    return (len(data) > 2 and data[0] & 15 == 8 and data[0] >> 4 <= 7
            and ((data[0] << 8) + data[1]) % 31 == 0)


def shape(data: bytes) -> float:
    """Strong syntax signals give intermediate encodings a search priority."""
    s = data.strip()
    if not s:
        return 0.0
    if s.startswith((b"\x1f\x8b\x08",b"BZh",b"\xfd7zXZ\0")):
        return 0.99
    if _zlib_header(s):
        return 0.98
    if len(s) > 6 and re.fullmatch(rb"[01\s,.;]+", s):
        return 0.96
    if re.fullmatch(rb"(?:\d{1,3}[\s,;]+)+\d{1,3}",s):
        return 0.92
    if re.fullmatch(rb"(?:\\x[0-9a-fA-F]{2})+",s):
        return 0.98
    if re.search(rb"%[0-9a-fA-F]{2}|&#\d+;|\\u[0-9a-fA-F]{4}",s):
        return 0.94
    compact = re.sub(rb"\s+",b"",s)
    if len(compact)>=4 and re.fullmatch(rb"[0-9A-Fa-f]+",compact) and len(compact)%2==0:
        return 0.85
    if len(compact)>=8 and re.fullmatch(rb"[A-Za-z2-7]+={0,6}",compact):
        return 0.91 if compact.endswith(b"=") else 0.77
    if len(compact)>=4 and re.fullmatch(rb"[A-Za-z0-9+/_-]+={0,2}",compact):
        if compact.endswith(b"="):
            return 0.92
        if any(48<=c<=57 for c in compact) and any(65<=c<=90 for c in compact):
            return 0.79
        return 0.58
    return 0.0


def _decompress(data: bytes) -> bytes | None:
    """Incremental size-limited decompression; never allocate an unbounded bomb."""
    if data.startswith(b"\x1f\x8b\x08"):
        obj = zlib.decompressobj(31)
    elif data.startswith(b"BZh"):
        obj = bz2.BZ2Decompressor()
    elif data.startswith(b"\xfd7zXZ\0"):
        obj = lzma.LZMADecompressor(memlimit=64*1024*1024)
    elif _zlib_header(data):
        obj = zlib.decompressobj()
    else:
        return None
    try:
        out = obj.decompress(data, MAX_OUTPUT+1)
        # No truncation, concatenated streams, or ignored trailing data.
        if len(out)>MAX_OUTPUT or not obj.eof or obj.unused_data:
            return None
        return out
    except (ValueError, OSError, EOFError, zlib.error, lzma.LZMAError):
        return None


def decode(data: bytes):
    raw = _decompress(data)
    if raw is not None:
        name = "Gzip" if data.startswith(b"\x1f\x8b") else "Bzip2" if data.startswith(b"BZh") else "XZ" if data.startswith(b"\xfd7z") else "Zlib"
        yield Transform(name, raw, "Complete stream; checksum/integrity verified by decoder", "compression", 0.05)
        return
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    s = text.strip()
    compact = re.sub(r"\s+", "", s)
    if not s:
        return
    # Whitespace is removed only as part of a named encoding's grammar.
    if re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]+",compact):
        h = compact[2:] if compact.startswith(("0x","0X")) else compact
        if len(h)%2==0:
            yield Transform("Hex",bytes.fromhex(h),"Two hex digits per byte")
    elif re.fullmatch(r"[0-9a-fA-F]{2}(?:[\s:,;-]+[0-9a-fA-F]{2})+",s):
        yield Transform("Hex",bytes.fromhex(re.sub(r"[\s:,;-]","",s)),"Delimited hex bytes")
    if re.fullmatch(r"(?:\\x[0-9a-fA-F]{2})+",compact):
        yield Transform("Hex escapes",bytes.fromhex(compact.replace("\\x","")),"\\xNN byte escapes")
    if re.fullmatch(r"0x[0-9a-fA-F]{2}(?:[\s,]+0x[0-9a-fA-F]{2})+",s):
        yield Transform("Hex byte list",bytes(int(v,16) for v in re.findall(r"0x([0-9a-fA-F]{2})",s)))
    if len(compact)>=2 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}",compact):
        try:
            out = base64.b64decode(compact+"="*(-len(compact)%4),validate=True)
            canonical = base64.b64encode(out).decode()
            if compact in (canonical, canonical.rstrip("=")):
                yield Transform("Base64",out,"Canonical alphabet and padding bits verified")
        except (binascii.Error, ValueError):
            pass
    if re.search("[-_]",compact) and re.fullmatch(r"[A-Za-z0-9_-]+={0,2}",compact):
        try:
            out=base64.b64decode(compact+"="*(-len(compact)%4),altchars=b"-_",validate=True)
            canonical = base64.urlsafe_b64encode(out).decode()
            if compact in (canonical, canonical.rstrip("=")):
                yield Transform("Base64 URL-safe",out,"Canonical URL-safe Base64")
        except (binascii.Error,ValueError):
            pass
    if len(compact)>=2 and re.fullmatch(r"[A-Za-z2-7]+={0,6}",compact):
        try:
            out=base64.b32decode(compact.upper()+"="*(-len(compact)%8))
            canonical = base64.b32encode(out).decode()
            if compact.upper() in (canonical, canonical.rstrip("=")):
                yield Transform("Base32",out,"RFC 4648; canonical padding bits verified")
        except (binascii.Error,ValueError):
            pass
    if 2<=len(compact)<=12000 and all(c in B58 for c in compact.encode()):
        n=0
        for c in compact.encode():
            n=n*58+B58.index(c)
        out=b"\0"*(len(compact)-len(compact.lstrip("1")))+n.to_bytes((n.bit_length()+7)//8,"big")
        yield Transform("Base58",out,"Bitcoin alphabet; no checksum claim",cost=0.65)
    if 2<=len(compact)<=64000:
        for name,fn,enc in [("Ascii85",base64.a85decode,base64.a85encode),
                            ("Base85",base64.b85decode,base64.b85encode)]:
            try:
                adobe = compact.startswith("<~") and compact.endswith("~>")
                if name=="Ascii85" and adobe:
                    out=fn(compact,adobe=True)
                    yield Transform("Ascii85 Adobe",out,"Adobe delimiters")
                else:
                    out=fn(compact)
                    if enc(out).decode()==compact:
                        yield Transform(name,out,"Round-trip verified",cost=0.75)
            except (ValueError, binascii.Error, OverflowError):
                pass
    bits=re.sub(r"[\s,.;]","",s)
    if len(bits)>=8 and len(bits)%8==0 and set(bits)<=set("01"):
        yield Transform("Binary",bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8)),"8-bit groups")
    if re.fullmatch(r"\d{1,3}(?:[\s,;]+\d{1,3})+",s):
        parts=re.split(r"[\s,;]+",s)
        values=[int(v) for v in parts]
        if max(values)<=255:
            yield Transform("Decimal bytes",bytes(values),"Decimal values in range 0–255")
        if all(re.fullmatch(r"[0-7]{2,3}",p) and int(p,8)<=255 for p in parts):
            yield Transform("Octal bytes",bytes(int(p,8) for p in parts),"Octal byte values")
    if re.fullmatch(r"(?:\\[0-7]{1,3})+",compact):
        values=[int(p,8) for p in compact.split("\\") if p]
        if max(values)<=255:
            yield Transform("Octal escapes",bytes(values))
    if "+" in text and not re.search(r"%(?![0-9a-fA-F]{2})",text):
        yield Transform("URL form",urllib.parse.unquote_to_bytes(text.replace("+"," ")),"Plus interpreted as space")
    if re.search(r"%[0-9a-fA-F]{2}",text) and not re.search(r"%(?![0-9a-fA-F]{2})",text):
        yield Transform("URL percent",urllib.parse.unquote_to_bytes(text),"Percent escapes; surrounding bytes preserved")
    if re.search(r"&(?:#\d+|#x[0-9a-fA-F]+|[A-Za-z]+);",text):
        out=html.unescape(text).encode("utf-8")
        if out!=data:
            yield Transform("HTML entities",out)
    if re.fullmatch(r"(?:\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|[^\\])+",text) and re.search(r"\\[uU]",text):
        try:
            out=text.encode("ascii").decode("unicode_escape").encode("utf-8")
            yield Transform("Unicode escapes",out)
        except (UnicodeError,ValueError):
            pass
    if re.search(r"=[0-9A-Fa-f]{2}|=\r?\n",text) and not re.search(r"=(?![0-9A-Fa-f]{2}|\r?\n)",text):
        import quopri
        out=quopri.decodestring(data)
        if out!=data:
            yield Transform("Quoted-printable",out)
    if re.fullmatch(r"[.\-/|\s]+",s) and re.search(r"[.-]",s):
        words=re.split(r"\s*[/|]\s*|\s{2,}",s)
        try:
            out=" ".join("".join(MORSE[c] for c in word.split()) for word in words).encode()
            if out:
                yield Transform("Morse",out,"Letter case is not represented in Morse")
        except KeyError:
            pass
