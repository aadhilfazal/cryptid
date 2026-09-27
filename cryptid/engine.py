"""Bounded best-first graph search. Every edge is a real byte transformation."""
from __future__ import annotations

import hashlib
import heapq
import itertools
import re
import time

from . import ciphers, codecs
from .models import Candidate, Result, Step
from .scoring import assess, preview

MAX_INPUT = 1024*1024


def diagnose(data: bytes) -> str:
    s=data.strip()
    if re.match(rb"\$(?:2[aby]|argon2id|argon2i|argon2d|[156y7])\$",s):
        return "Password-hash format: one-way; hash recovery is outside this version."
    if re.fullmatch(rb"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128}",s):
        return "Hash-sized hex string; could also be ordinary encoded bytes. The algorithm is ambiguous."
    if s.startswith((b"Salted__",b"-----BEGIN ",b"$ANSIBLE_VAULT")):
        return "Recognised envelope; modern key-based decryption is outside this version."
    return "No supported route reached convincing English, a known flag wrapper, or structured text."


def solve(data: bytes, *, deep: bool=False, top: int=3) -> Result:
    if not data:
        raise ValueError("empty input")
    if len(data)>MAX_INPUT:
        raise ValueError("input exceeds the 1 MiB limit; split it into separate challenges")
    start=time.monotonic()
    deadline=start+(35.0 if deep else 7.0)
    max_states=2400 if deep else 500
    max_depth=128 if deep else 64
    max_memory=48*1024*1024 if deep else 24*1024*1024
    root=Candidate(data,(),assess(data))
    # Do not 'decrypt' convincing existing plaintext into an accidental match.
    if root.assessment.score>=0.87 and root.assessment.kind!="binary" and codecs.shape(data)<0.85:
        return Result([root],"already-plaintext",1,time.monotonic()-start,
                      "Input already looks like plaintext; no transformations applied.")
    serial=itertools.count()
    queue=[]
    seen={hashlib.sha256(data).digest():0.0}
    memory=len(data)
    candidates=[root]
    retained={hashlib.sha256(data).digest():root}
    visited=0
    limits=[]
    advanced_done=set()
    # A separate backlog allows fast decoding to finish before expensive attacks.
    backlog=[]

    def enqueue(t, parent):
        nonlocal memory
        if t.data==parent.data or not t.data or len(t.data)>codecs.MAX_OUTPUT:
            return
        depth=len(parent.steps)+1
        if depth>max_depth:
            if "layer limit" not in limits: limits.append("layer limit")
            return
        digest=hashlib.sha256(t.data).digest()
        cost=parent.cost+t.cost
        if seen.get(digest,float("inf"))<=cost:
            return
        if memory+len(t.data)>max_memory:
            if "memory budget" not in limits: limits.append("memory budget")
            return
        seen[digest]=cost
        memory+=len(t.data)
        step=Step(t.name,t.detail,len(parent.data),len(t.data),preview(t.data))
        node=Candidate(t.data,parent.steps+(step,),assess(t.data),cost)
        old=retained.get(digest)
        if old is None or node.rank>old.rank:
            retained[digest]=node
        priority=max(node.assessment.score,codecs.shape(node.data)*0.95)
        if t.family=="cipher":
            priority=max(priority,ciphers.potential(node.data[:4096],lookahead=True))
        if t.family in ("encoding","compression"):
            floor=0.93 if t.cost<0.6 else 0.90
            priority=max(priority,floor)
        priority-=min(.12,cost*.003)
        # Verified layers are cheap; weak decoders and cipher guesses need evidence.
        if priority>=0.42:
            heapq.heappush(queue,(-priority,next(serial),node,0))

    heapq.heappush(queue,(-max(root.assessment.score,codecs.shape(data)),next(serial),root,0))
    advanced_rounds=0
    cipher_rounds=0

    def do_advanced():
        nonlocal advanced_rounds
        pool=[c for c in backlog if hashlib.sha256(c.data).digest() not in advanced_done
              and codecs.shape(c.data)<0.85]
        if not pool or advanced_rounds >= (12 if deep else 4):
            return False
        # Prefer original or cheaply unwrapped ciphertext to compounded guesses.
        node=min(pool,key=lambda c:(c.cost,-c.assessment.score))
        advanced_done.add(hashlib.sha256(node.data).digest())
        advanced_rounds+=1
        for t in ciphers.advanced(node.data,deadline,deep):
            enqueue(t,node)
            # Return to the queue as soon as a strong terminal candidate exists.
            # Do not spend the remaining budget on unrelated statistical attacks.
            evidence = assess(t.data)
            if evidence.score >= 0.94 and codecs.shape(t.data) < 0.85:
                break
        return True

    while True:
        if time.monotonic()>=deadline:
            limits.append("time budget"); break
        if visited>=max_states:
            limits.append("state budget"); break
        if not queue:
            # Prioritise unresolved high-quality leaves for bounded statistical work.
            if not do_advanced():
                break
            continue
        _,_,node,phase=heapq.heappop(queue)
        if phase==1:
            cipher_rounds+=1
            for t in ciphers.fast(node.data,deep):
                if time.monotonic()>=deadline: break
                enqueue(t,node)
            if 12<=len(node.data)<=16000:
                backlog.append(node)
            if cipher_rounds%24==0:
                do_advanced()
            continue
        visited+=1
        if node.assessment.kind=="flag" and node.assessment.score>=0.99:
            # The flag body is not modified; a known wrapper is strong CTF evidence.
            break
        if node.steps and node.assessment.score>=0.89 and codecs.shape(node.data)<0.85:
            # Keep this terminal candidate while queued alternatives finish a few
            # more cheap expansions. Never transform a strong plaintext further.
            break
        if node.assessment.kind=="binary":
            break
        if len(node.steps)>=max_depth:
            if "layer limit" not in limits: limits.append("layer limit")
            continue
        decoded=list(codecs.decode(node.data))
        for t in decoded:
            enqueue(t,node)
        for t in ciphers.quick(node.data):
            enqueue(t,node)
        # Very large inputs still decode, but brute-force work has a smaller cap.
        explicit={"Binary","Decimal bytes","Octal bytes","Hex escapes","Hex byte list",
                  "Octal escapes",
                  "Gzip","Bzip2","XZ","Zlib"}
        if len(node.data)<=64000 and not any(t.name in explicit for t in decoded):
            useful=any(assess(t.data).score>=0.76 or codecs.shape(t.data)>=0.65 for t in decoded)
            priority=(0.35 if useful else 0.85)-min(.12,node.cost*.005)
            heapq.heappush(queue,(-priority,next(serial),node,1))
    candidates=sorted(retained.values(),key=lambda c:(c.rank,-len(c.steps)),reverse=True)
    best=candidates[0]
    # If no useful terminal result exists, report the most promising progressed
    # node rather than disguising the original encoded string as recovered text.
    if best.assessment.score<0.76:
        progressed=[c for c in candidates if c.steps]
        if progressed:
            partial=max(progressed,key=lambda c:(codecs.shape(c.data),c.assessment.score,-c.cost))
            candidates=[partial]+[c for c in candidates if c is not partial]
            best=partial
    if best.assessment.kind=="binary" and best.steps:
        status="decoded-binary"; reason=best.assessment.evidence
    elif best.assessment.score>=0.87:
        status="likely-plaintext" if best.steps else "already-plaintext"
        reason="Strong plaintext candidate. Appearance is not mathematical proof that every original layer is gone."
    elif best.assessment.score>=0.76:
        status="ambiguous"; reason="Plausible text, but insufficient evidence to call the recovery complete."
    else:
        status="incomplete" if limits else "unresolved"
        reason=diagnose(best.data)
    if limits and status not in ("likely-plaintext","already-plaintext","decoded-binary"):
        status="incomplete"
    return Result(candidates[:top],status,visited,time.monotonic()-start,reason,list(dict.fromkeys(limits)))
