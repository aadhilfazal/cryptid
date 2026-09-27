"""Small-key exhaustive searches and bounded statistical classical solvers."""
from __future__ import annotations

from collections import Counter
from functools import lru_cache
import itertools
import math
import random
import re
import time

from .codecs import decode, shape
from .models import Transform
from .scoring import assess, column_score, FLAG, FREQ, language_model, printable, quad_score

XOR_TABLES = tuple(bytes(b ^ k for b in range(256)) for k in range(256))


@lru_cache(maxsize=400)
def affine_table(a, b):
    inv = pow(a, -1, 26)
    table = bytearray(range(256))
    for start in (65,97):
        for c in range(26):
            table[start+c] = start + (inv*(c-b))%26
    return bytes(table)


@lru_cache(maxsize=2400)
def potential(data: bytes, lookahead=False) -> float:
    """Encoded intermediate results matter as well as English terminal text."""
    score=max(assess(data).score, shape(data)*0.92)
    if lookahead and shape(data) >= 0.75 and len(data) <= 16000:
        for t in decode(data):
            score=max(score, assess(t.data).score,shape(t.data)*0.93)
            if shape(t.data)>=0.70:
                score=max(score,0.94)
    return score


def quick(data: bytes):
    """Cheap transforms compete with coincidental encoding syntax immediately."""
    if not data or len(data)>64000:
        return
    # A whole known flag gives direct XOR evidence even when ciphertext happens
    # to look like quoted-printable. Consider this path before lossy guesses.
    if len(data) <= 4096:
        for key in sorted({data[0] ^ c for c in b'fFcChHkKpPtT \t\r\n'} - {0}):
            out = data.translate(XOR_TABLES[key])
            if out.isascii() and FLAG.fullmatch(out.decode('ascii').strip()):
                yield Transform('Single-byte XOR', out,
                                f'key 0x{key:02x}; whole known flag wrapper', 'cipher', 1.35)
    if printable(data[:4096])<0.98:
        return
    if len(data) <= 4096 and re.fullmatch(rb'[A-Za-z]{3,7}\{[^{}\r\n]+\}', data.strip()):
        for a in (1,3,5,7,9,11,15,17,19,21,23,25):
            for b in range(26):
                if a == 1 and b == 0:
                    continue
                out = data.translate(affine_table(a,b))
                if out.isascii() and FLAG.fullmatch(out.decode('ascii').strip()):
                    name = 'ROT13' if a == 1 and b == 13 else 'Caesar' if a == 1 else 'Affine'
                    yield Transform(name, out,
                                    f'encryption parameters a={a}, b={b}; inverse applied', 'cipher',
                                    1.1 if a == 1 else 2.0)
    values=[("Reverse",data[::-1],"Reverse byte order"),
            ("ROT13",data.translate(affine_table(1,13)),"Decrypt by subtracting 13 (mod 26)"),
            ("ROT47",data.translate(bytes(33+(b-33+47)%94 if 33<=b<=126 else b for b in range(256))),"Rotate printable ASCII by 47"),
            ("Atbash",data.translate(bytes(155-b if 65<=b<=90 else 219-b if 97<=b<=122 else b for b in range(256))),"Reverse A–Z and a–z")]
    for name,out,detail in values:
        if out!=data and potential(out[:4096],True)>=0.88:
            yield Transform(name,out,detail,"cipher",1.1)


def fast(data: bytes, deep: bool=False):
    if not data or len(data)>64000:
        return
    sample=data[:4096]
    if printable(sample) > 0.98:
        if any(65<=b<=90 or 97<=b<=122 for b in sample):
            # ROT13 and consecutive Caesar layers collapse to one shift modulo 26.
            for shift in range(1,26):
                out=data.translate(affine_table(1,shift))
                if potential(out[:4096]) >= 0.59:
                    yield Transform("ROT13" if shift==13 else "Caesar",out,
                                    f"Decrypt by subtracting {shift} (mod 26); searched all shifts",
                                    "cipher",1.1)
            table=bytes(155-b if 65<=b<=90 else 219-b if 97<=b<=122 else b for b in range(256))
            out=data.translate(table)
            if potential(out[:4096])>=0.59:
                yield Transform("Atbash",out,"Reverse A–Z and a–z", "cipher",1.3)
        out=data.translate(bytes(33+(b-33+47)%94 if 33<=b<=126 else b for b in range(256)))
        if potential(out[:4096])>=0.59:
            yield Transform("ROT47",out,"Rotate printable ASCII by 47", "cipher",1.3)
        out=data[::-1]
        if potential(out[:4096])>=0.64:
            yield Transform("Reverse",out,"Reverse byte order", "cipher",1.5)
    # C-level translations make 256 single-byte candidates inexpensive. Rank on
    # a sample, then apply each selected key to the complete unmodified data.
    ranked=[]
    for key in range(1,256):
        part=sample.translate(XOR_TABLES[key])
        if printable(part) < 0.97 and shape(part)<0.9:
            continue
        score=potential(part,lookahead=True)
        if score>=0.60:
            ranked.append((score,key))
    for score,key in sorted(ranked,reverse=True)[:(16 if deep else 8)]:
        yield Transform("Single-byte XOR",data.translate(XOR_TABLES[key]),
                        f"key 0x{key:02x}; all 256 keys considered (0 is unchanged)","cipher",1.35)


def rail_decode(data: bytes, rails: int) -> bytes:
    cycle=2*(rails-1)
    positions=[min(i%cycle,cycle-i%cycle) for i in range(len(data))]
    counts=Counter(positions)
    chunks=[]
    offset=0
    for r in range(rails):
        chunks.append(iter(data[offset:offset+counts[r]]))
        offset+=counts[r]
    return bytes(next(chunks[r]) for r in positions)


def vigenere_decode(data: bytes, key: list[int]) -> bytes:
    out=bytearray(data)
    index=0
    for i,b in enumerate(data):
        start=65 if 65<=b<=90 else 97 if 97<=b<=122 else None
        if start is not None:
            out[i]=start+(b-start-key[index%len(key)])%26
            index+=1
    return bytes(out)


def _chi(column: list[int], shift: int) -> float:
    counts=Counter((c-shift)%26 for c in column)
    n=len(column)
    return sum((counts[i]-n*FREQ[i]/100)**2/max(.2,n*FREQ[i]/100) for i in range(26))


def _vigenere(data: bytes, deadline: float, deep: bool):
    letters=[(b|32)-97 for b in data if 65<=b<=90 or 97<=b<=122]
    if len(letters)<60:
        return
    n=len(letters)
    lengths=[]
    for size in range(2,min(32 if deep else 18,n//8)+1):
        cols=[letters[i::size] for i in range(size)]
        ioc=sum(sum(c*(c-1) for c in Counter(col).values())/max(1,len(col)*(len(col)-1)) for col in cols)/size
        lengths.append((ioc,size))
    for _,size in sorted(lengths,reverse=True)[:(10 if deep else 6)]:
        if time.monotonic()>deadline:
            break
        choices=[sorted(range(26),key=lambda k:_chi(letters[i::size],k))[:4] for i in range(size)]
        key=[c[0] for c in choices]
        part=data[:1800]
        def merit(k):
            return quad_score(vigenere_decode(part,k).decode("ascii"))
        current=merit(key)
        for _ in range(2):
            for pos in range(size):
                bestkey=key[pos]
                for k in choices[pos]:
                    trial=key.copy(); trial[pos]=k
                    score=merit(trial)
                    if score>current:
                        current=score; bestkey=k
                key[pos]=bestkey
        out=vigenere_decode(data,key)
        if assess(out).score>=0.76:
            # Reduce a repeated recovered keyword to its shortest period.
            for p in range(1,len(key)+1):
                if all(key[i]==key[i%p] for i in range(len(key))):
                    key=key[:p]; break
            yield Transform("Vigenère",out,"estimated key "+''.join(chr(k+65) for k in key),"cipher",2.5)


def _repeating_xor(data: bytes, deadline: float, deep: bool):
    if not 80<=len(data)<=16000:
        return
    sample=data[:1800]
    distances=[]
    for size in range(2,min(64 if deep else 40,len(sample)//6)+1):
        blocks=[sample[i*size:(i+1)*size] for i in range(6)]
        pairs=list(itertools.combinations(blocks,2))
        distance=sum(sum((a^b).bit_count() for a,b in zip(x,y)) for x,y in pairs)/(len(pairs)*size)
        distances.append((distance,size))
    likelihood=[column_score(bytes([b])) for b in range(256)]
    keys_seen=set()
    for _,size in sorted(distances)[:(12 if deep else 7)]:
        if time.monotonic()>deadline:
            break
        key=[]
        for pos in range(size):
            counts=list(Counter(sample[pos::size]).items())
            k=max(range(256),key=lambda k:sum(n*likelihood[b^k] for b,n in counts))
            key.append(k)
        key=bytes(key)
        for p in range(1,len(key)+1):
            if all(key[i]==key[i%p] for i in range(len(key))):
                key=key[:p]; break
        if key in keys_seen:
            continue
        keys_seen.add(key)
        out=bytes(b^key[i%len(key)] for i,b in enumerate(data))
        if assess(out).score>=0.76:
            yield Transform("Repeating-key XOR",out,f"estimated key hex {key.hex()}","cipher",2.8)


def _columnar(data: bytes, deadline: float, deep: bool):
    if not 30<=len(data)<=1800:
        return
    best=[]
    for width in range(2,7 if deep else 5):
        lengths=[(len(data)+width-1-i)//width for i in range(width)]
        for order in itertools.permutations(range(width)):
            if time.monotonic()>deadline:
                return
            cols=[b""]*width; start=0
            for col in order:
                cols[col]=data[start:start+lengths[col]]; start+=lengths[col]
            out=bytes(cols[i%width][i//width] for i in range(len(data)))
            score=assess(out).score
            if score>=0.80:
                best.append((score,order,out))
    for _,order,out in sorted(best,reverse=True)[:3]:
        yield Transform("Columnar transposition",out,"read columns "+','.join(str(i+1) for i in order),"cipher",3.0)


def _substitution(data: bytes, deadline: float):
    """Deterministic annealing, with delta scoring of affected quadgrams only."""
    letters=[(b|32)-97 for b in data if 65<=b<=90 or 97<=b<=122]
    if len(letters)<160:
        return
    letters=letters[:1800]
    _,logs,floor=language_model()
    quads=list(Counter(tuple(letters[i:i+4]) for i in range(len(letters)-3)).items())
    indexes=[set() for _ in range(26)]
    for i,(quad,_) in enumerate(quads):
        for c in quad: indexes[c].add(i)
    logcache={tuple(ord(c)-97 for c in q):v for q,v in logs.items()}
    cipher_order=[c for c,_ in Counter(letters).most_common()]
    cipher_order += [c for c in range(26) if c not in cipher_order]
    english_order=sorted(range(26),key=lambda c:FREQ[c],reverse=True)
    initial=[0]*26
    for c,e in zip(cipher_order,english_order): initial[c]=e
    rng=random.Random(0)
    overall=(-math.inf,initial)
    for restart in range(6):
        key=initial.copy()
        if restart:
            for _ in range(restart*3):
                a,b=rng.sample(range(26),2); key[a],key[b]=key[b],key[a]
        def qvalue(i):
            quad,count=quads[i]
            return logcache.get(tuple(key[c] for c in quad),floor)*count
        values=[qvalue(i) for i in range(len(quads))]
        current=sum(values)
        for turn in range(5000):
            if turn%100==0 and time.monotonic()>deadline:
                break
            a,b=rng.sample(range(26),2)
            affected=indexes[a]|indexes[b]
            old=sum(values[i] for i in affected)
            key[a],key[b]=key[b],key[a]
            updated=[(i,qvalue(i)) for i in affected]
            delta=sum(v for _,v in updated)-old
            temp=max(0.25,12.0*(1-turn/5000))
            if delta>=0 or rng.random()<math.exp(max(-700,delta/temp)):
                for i,v in updated: values[i]=v
                current+=delta
                if current>overall[0]: overall=(current,key.copy())
            else:
                key[a],key[b]=key[b],key[a]
        if time.monotonic()>deadline:
            break
    key=overall[1]
    table=bytearray(range(256))
    for start in (65,97):
        for c in range(26): table[start+c]=start+key[c]
    out=data.translate(bytes(table))
    if assess(out).score>=0.80:
        yield Transform("Substitution",out,"estimated A–Z plaintext mapping "+''.join(chr(k+65) for k in key),"cipher",3.5)


def advanced(data: bytes, deadline: float, deep: bool=False):
    if not 12<=len(data)<=16000 or time.monotonic()>deadline:
        return
    text_ok=data.isascii() and printable(data[:4096])>0.99
    if text_ok:
        ranked=[]
        for a in (3,5,7,9,11,15,17,19,21,23,25):
            for b in range(26):
                if time.monotonic()>deadline: return
                out=data.translate(affine_table(a,b))
                score=potential(out[:1800])
                if score>=0.76:
                    ranked.append((score,a,b,out))
        for _,a,b,out in sorted(ranked,reverse=True)[:5]:
            yield Transform("Affine",out,f"encryption parameters a={a}, b={b}; inverse applied","cipher",2.0)
        for rails in range(2,min(32 if deep else 16,len(data)//2)+1):
            if time.monotonic()>deadline: return
            out=rail_decode(data,rails)
            if potential(out[:1800])>=0.77:
                yield Transform("Rail Fence",out,f"{rails} rails; standard zigzag, offset 0","cipher",2.2)
        yield from _vigenere(data,deadline,deep)
        yield from _columnar(data,deadline,deep)
        if deep and time.monotonic()<deadline:
            yield from _substitution(data,min(deadline,time.monotonic()+5),)
    # Statistical XOR requires enough bytes; it works on binary ciphertext too.
    if time.monotonic()<deadline:
        yield from _repeating_xor(data,deadline,deep)
