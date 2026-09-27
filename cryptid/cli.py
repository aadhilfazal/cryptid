"""Linux CLI. Banner on stderr in raw mode; stdout remains byte-exact."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import tempfile

from . import AUTHOR, AUTHOR_URL, __version__
from .engine import MAX_INPUT, solve
from .scoring import preview

BANNER = f"CRYPTID {__version__} | {AUTHOR} (@aadhilfazal)\n{AUTHOR_URL}"
SUCCESS = {"likely-plaintext", "already-plaintext", "decoded-binary"}
SCHEMES = """Automatic formats
  Base64, Base64 URL-safe, Base32, hex / hex escapes / hex byte lists
  Base58 (Bitcoin alphabet), Base85, Ascii85 / Adobe Ascii85
  binary (8-bit groups), decimal bytes, octal bytes / escapes
  URL percent / form encoding, HTML entities, Unicode escapes
  quoted-printable, Morse, gzip, zlib, bzip2, xz

Classical recovery
  Caesar (all 26 shifts, including ROT13), ROT47, Atbash, reversed bytes
  single-byte XOR (all 256 keys considered)
  Affine, Rail Fence, Vigenère, repeating-key XOR
  columnar transposition: 2–4 columns normally, 2–6 with --deep
  substitution: statistical annealing with --deep, at least 160 letters

Statistical attacks need enough English text and may return partial/incorrect
candidates. Encodings can repeat. Input and decompression budgets are bounded.
No modern decryption, hash cracking, external AI, network calls, or JSON mode.
"""


def parser():
    p=argparse.ArgumentParser(prog="cryptid",allow_abbrev=False,
        description=BANNER+"\nAutomatically recover English and CTF plaintext through layered encodings.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  cryptid 'aGVsbG8gd29ybGQ='\n  cryptid -f secret.txt --deep -v\n"
               "  cryptid -f secret.txt -o answer.txt --report trace.txt\n"
               "  printf '%s' 'aGVsbG8=' | cryptid -d\n\n"
               "No layer count is required. --deep increases internal search budgets.")
    p.add_argument("text",nargs="?",help="encoded text (quote spaces), or pipe bytes on stdin")
    p.add_argument("-f","--file",metavar="FILE",help="read a text or binary file")
    p.add_argument("-o","--output",metavar="FILE",help="save the selected recovered bytes exactly")
    p.add_argument("-d","--decode-only",action="store_true",help="raw recovered bytes on stdout; watermark on stderr")
    p.add_argument("-v","--verbose",action="store_true",help="show intermediate previews and evidence")
    p.add_argument("--deep",action="store_true",help="broader search and statistical substitution solving")
    p.add_argument("--top",type=int,default=3,metavar="N",help="show up to N ranked candidates (1–10; default 3)")
    p.add_argument("--report",metavar="FILE",help="save a readable result and full step trace")
    p.add_argument("--list",action="store_true",help="list supported methods and limits")
    p.add_argument("-V","--version",action="version",version=BANNER)
    return p


def render(result,verbose=False,full=False):
    best=result.best
    lines=[BANNER,"",f"STATUS   {result.status.upper()}"]
    if best.steps:
        lines.extend(["","DECODING STEPS"])
        for i,step in enumerate(best.steps,1):
            lines.append(f"  {i:02d}. {step.name}  ({step.before} → {step.after} bytes)")
            if step.detail: lines.append("      "+step.detail)
            if verbose: lines.append("      Output: "+step.preview)
    else:
        lines.extend(["","No decoding steps applied."])
    lines.extend(["","RESULT   "+preview(best.data,len(best.data)+1 if full else 500),
                  "EVIDENCE "+best.assessment.evidence,"",result.reason])
    if result.status=="decoded-binary":
        lines.append("A binary file was recovered; this is not a plaintext claim.")
    if result.limits:
        lines.append("Budget reached: "+", ".join(result.limits)+". Search was not exhaustive.")
    if len(result.candidates)>1:
        lines.extend(["","OTHER CANDIDATES (heuristic order, not confidence percentages)"])
        for i,c in enumerate(result.candidates[1:],2):
            route=" → ".join(s.name for s in c.steps) or "unchanged input"
            lines.append(f"  {i}. {route}: {preview(c.data,90)}")
    lines.extend(["",f"Searched {result.visited} states in {result.elapsed:.2f}s.",
                  "Steps show the route found; the original encoding history may not be unique."])
    return "\n".join(lines)+"\n"


def atomic_write(path: Path, data: bytes):
    """Create complete output or leave an existing destination unchanged."""
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(prefix=".cryptid-",dir=path.parent,delete=False) as fh:
            temporary=Path(fh.name)
            fh.write(data)
            fh.flush()
        os.replace(temporary,path)
    finally:
        if temporary is not None and temporary.exists(): temporary.unlink()


def main(argv=None):
    p=parser(); args=p.parse_args(argv)
    if not 1<=args.top<=10: p.error("--top must be between 1 and 10")
    if args.list:
        print(BANNER+"\n\n"+SCHEMES); return 0
    if args.file is not None and args.text is not None:
        p.error("choose a file or a text argument")
    destinations=[Path(x).expanduser() for x in (args.output,args.report) if x]
    resolved=[p.resolve() for p in destinations]
    if len(set(resolved))!=len(resolved): p.error("output and report must be different files")
    if args.file and Path(args.file).expanduser().resolve() in resolved:
        p.error("output/report cannot overwrite the input file")
    try:
        if args.file:
            with Path(args.file).expanduser().open("rb") as fh: data=fh.read(MAX_INPUT+1)
        elif args.text is not None:
            data=args.text.encode("utf-8")
        elif not sys.stdin.isatty():
            data=sys.stdin.buffer.read(MAX_INPUT+1)
        else:
            p.print_help(); return 2
        if args.decode_only: print(BANNER,file=sys.stderr)
        elif sys.stderr.isatty(): print("Cryptid is searching…",file=sys.stderr)
        result=solve(data,deep=args.deep,top=args.top)
        if args.report:
            atomic_write(Path(args.report).expanduser(),render(result,True,True).encode("utf-8"))
        if result.status in SUCCESS:
            if args.output: atomic_write(Path(args.output).expanduser(),result.best.data)
            if args.decode_only: sys.stdout.buffer.write(result.best.data)
            else: print(render(result,args.verbose),end="")
            return 0
        if args.decode_only:
            print(f"cryptid: {result.status}: {result.reason}",file=sys.stderr)
        else:
            print(render(result,args.verbose),end="")
        if args.output:
            print("cryptid: no output file written; recovery is unresolved/ambiguous",file=sys.stderr)
        return 3 if result.status=="incomplete" else 1
    except (OSError,ValueError) as exc:
        print(f"cryptid: {exc}",file=sys.stderr); return 2
    except KeyboardInterrupt:
        print("\ncryptid: interrupted",file=sys.stderr); return 130


def entrypoint():
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        # Avoid a second exception from interpreter shutdown when a pipe closes.
        os.dup2(os.open(os.devnull,os.O_WRONLY),sys.stdout.fileno())
        raise SystemExit(0)

