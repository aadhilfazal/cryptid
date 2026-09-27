#!/usr/bin/env python3
"""Build cryptid.zip from source and refresh the included SHA256SUMS manifest."""
import argparse
import hashlib
from pathlib import Path
import stat
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {'.git', '.venv', '__pycache__', '.pytest_cache', 'build', 'dist'}


def source_files():
    return sorted(p for p in ROOT.rglob('*')
                  if p.is_file() and not p.is_symlink()
                  and not any(part in SKIP_DIRS or part.endswith('.egg-info')
                              for part in p.relative_to(ROOT).parts)
                  and p.suffix not in {'.pyc', '.pyo', '.zip', '.whl'}
                  and p.name not in {'SHA256SUMS', '.coverage', 'answer.txt', 'trace.txt'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist/cryptid.zip')
    args = parser.parse_args()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    files = source_files()
    manifest = ROOT / 'SHA256SUMS'
    manifest.write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  '
                               f'{p.relative_to(ROOT).as_posix()}\n' for p in files), encoding='utf-8')
    # Fixed metadata makes the archive reproducible for identical source bytes.
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(files + [manifest]):
            info = zipfile.ZipInfo('cryptid/' + path.relative_to(ROOT).as_posix(), (2026,9,27,0,0,0))
            info.compress_type = zipfile.ZIP_DEFLATED
            mode = 0o755 if path.name in {'install.sh', 'cryptid.py'} else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.create_system = 3
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    print(f'{output}: {len(files)+1} files; {output.stat().st_size:,} bytes')


if __name__ == '__main__':
    main()
