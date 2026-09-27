#!/usr/bin/env python3
"""Independent forward encoders generate reproducible end-to-end challenges.

No decoder implementation is imported. Expected bytes are recorded separately.
All encoders in this module are independent of the application decoder.
"""
import argparse
import base64
import bz2
import codecs
import csv
import gzip
import html
import io
import itertools
import lzma
from pathlib import Path
import random
import re
import zlib
import urllib.parse

ROOT=Path(__file__).resolve().parents[1]
ALPH="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def caesar(data,k):
    text=data.decode('ascii')
    out=[]
    for c in text:
        if 'A'<=c<='Z': out.append(chr(65+(ord(c)-65+k)%26))
        elif 'a'<=c<='z': out.append(chr(97+(ord(c)-97+k)%26))
        else: out.append(c)
    return ''.join(out).encode()


def b58(data):
    num=int.from_bytes(data,'big'); out=''
    while num:
        num,r=divmod(num,58); out=ALPH[r]+out
    return ('1'*(len(data)-len(data.lstrip(b'\0')))+out).encode()


def affine(data,a=5,b=8):
    out=bytearray()
    for c in data:
        start=65 if 65<=c<=90 else 97 if 97<=c<=122 else None
        out.append(start+(a*(c-start)+b)%26 if start is not None else c)
    return bytes(out)


def rail(data,rails=3):
    rows=[bytearray() for _ in range(rails)]; r=0; direction=1
    for b in data:
        rows[r].append(b)
        if r==0: direction=1
        elif r==rails-1: direction=-1
        r+=direction
    return b''.join(rows)


def vig(data,key=b'LEMON'):
    out=bytearray(); i=0
    for b in data:
        start=65 if 65<=b<=90 else 97 if 97<=b<=122 else None
        if start is None: out.append(b)
        else:
            out.append(start+(b-start+key[i%len(key)]-65)%26); i+=1
    return bytes(out)


def columnar(data,key='ZEBRA'):
    return b''.join(data[i::len(key)] for i in sorted(range(len(key)),key=lambda i:key[i]))


def substitution(data):
    rng=random.Random(431); alphabet=list(range(26)); rng.shuffle(alphabet)
    return bytes(65+alphabet[b-65] if 65<=b<=90 else 97+alphabet[b-97] if 97<=b<=122 else b for b in data)


ENCODERS={
 'base64':base64.b64encode,'base32':base64.b32encode,'hex':lambda d:d.hex().encode(),
 'base85':base64.b85encode,'ascii85':base64.a85encode,'base58':b58,
 'binary':lambda d:' '.join(f'{b:08b}' for b in d).encode(),
 'decimal':lambda d:' '.join(str(b) for b in d).encode(),
 'octal':lambda d:' '.join(f'{b:03o}' for b in d).encode(),
 'hex-escapes':lambda d:''.join(f'\\x{b:02x}' for b in d).encode(),
 'octal-escapes':lambda d:''.join(f'\\{b:03o}' for b in d).encode(),
 'url':lambda d:''.join(f'%{b:02X}' for b in d).encode(),
 'html':lambda d:''.join(f'&#{b};' for b in d).encode(),
 'unicode':lambda d:''.join(f'\\u{b:04x}' for b in d).encode(),
 'quoted-printable':lambda d:''.join(f'={b:02X}' for b in d).encode(),
 'gzip':lambda d:gzip.compress(d,mtime=0),'zlib':zlib.compress,'bzip2':bz2.compress,'xz':lzma.compress,
 'caesar7':lambda d:caesar(d,7),'rot13':lambda d:caesar(d,13),
 'xor42':lambda d:bytes(b^0x42 for b in d),'xorFF':lambda d:bytes(b^0xff for b in d),
 'atbash':lambda d:bytes(155-b if 65<=b<=90 else 219-b if 97<=b<=122 else b for b in d),
 'rot47':lambda d:bytes(33+(b-33+47)%94 if 33<=b<=126 else b for b in d),
 'reverse':lambda d:d[::-1],
}


# Separate forward definitions; never import Cryptid's reverse transforms.
MORSE_ALPHABET = dict(zip(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,?/-@:=',
    '.- -... -.-. -.. . ..-. --. .... .. .--- -.- .-.. -- -. --- .--. --.- .-. ... - ..- ...- .-- -..- -.-- --..'.split()
    + '----- .---- ..--- ...-- ....- ..... -.... --... ---.. ----. .-.-.- --..-- ..--.. -..-. -....- .--.-. ---... -...-'.split(),
))


def morse(data):
    return ' / '.join(' '.join(MORSE_ALPHABET[c] for c in word)
                      for word in data.decode('ascii').split(' ')).encode()


def substitute(data, seed):
    alphabet = list(range(26))
    random.Random(seed).shuffle(alphabet)
    return bytes(65 + alphabet[b-65] if 65 <= b <= 90 else
                 97 + alphabet[b-97] if 97 <= b <= 122 else b for b in data)


ENCODERS.update({
    'base64-url': base64.urlsafe_b64encode,
    'base64-unpadded': lambda d: base64.b64encode(d).rstrip(b'='),
    'base64-wrapped': lambda d: b'\n'.join(base64.b64encode(d)[i:i+32] for i in range(0, len(base64.b64encode(d)), 32)),
    'base32-lower': lambda d: base64.b32encode(d).lower(),
    'base32-unpadded': lambda d: base64.b32encode(d).rstrip(b'='),
    'hex-upper': lambda d: d.hex().upper().encode(),
    'hex-prefix': lambda d: b'0x' + d.hex().encode(),
    'hex-delimited': lambda d: ':'.join(f'{b:02x}' for b in d).encode(),
    'hex-list': lambda d: ', '.join(f'0x{b:02x}' for b in d).encode(),
    'ascii85-adobe': lambda d: base64.a85encode(d, adobe=True),
    'binary-compact': lambda d: ''.join(f'{b:08b}' for b in d).encode(),
    'decimal-comma': lambda d: ','.join(str(b) for b in d).encode(),
    'octal-semicolon': lambda d: ';'.join(f'{b:03o}' for b in d).encode(),
    'url-form': lambda d: urllib.parse.quote_plus(d, safe='').encode(),
    'html-hex': lambda d: ''.join(f'&#x{b:x};' for b in d).encode(),
    'unicode-long': lambda d: ''.join(f'\\U{b:08x}' for b in d).encode(),
    'quoted-printable-soft': lambda d: b'=\r\n'.join(''.join(f'={b:02X}' for b in d[i:i+16]).encode() for i in range(0,len(d),16)),
    'morse': morse,
})
