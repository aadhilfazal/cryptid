#!/bin/sh
# Offline user installation. Optional argument is a prefix, not a bin directory.
# sh install.sh             -> ~/.local/bin/cryptid
# sh install.sh /some/path  -> /some/path/bin/cryptid
set -eu
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREFIX=${1:-"$HOME/.local"}
command -v python3 >/dev/null 2>&1 || { echo "Python 3.10+ is required." >&2; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' || {
    echo "Python 3.10+ is required." >&2; exit 1;
}
python3 - "$SRC" "$PREFIX" <<'PY'
import os, pathlib, shlex, shutil, sys, tempfile
src=pathlib.Path(sys.argv[1]).resolve()
prefix=pathlib.Path(sys.argv[2]).expanduser().resolve()
app_root=prefix/'share'/'cryptid'
bin_dir=prefix/'bin'
app_root.mkdir(parents=True,exist_ok=True)
bin_dir.mkdir(parents=True,exist_ok=True)
# Versioned install: a failed copy cannot destroy the working installation.
target=pathlib.Path(tempfile.mkdtemp(prefix='1.0.0-',dir=app_root))
try:
    shutil.copytree(src/'cryptid',target/'cryptid',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    for name in ('cryptid.py','LICENSE','README.md'):
        shutil.copy2(src/name,target/name)
    script='#!/bin/sh\nexec '+shlex.quote(sys.executable)+' '+shlex.quote(str(target/'cryptid.py'))+' "$@"\n'
    fd,name=tempfile.mkstemp(prefix='.cryptid-',dir=bin_dir)
    with os.fdopen(fd,'w') as fh: fh.write(script)
    os.chmod(name,0o755)
    os.replace(name,bin_dir/'cryptid')
except BaseException:
    shutil.rmtree(target)
    raise
print('Installed:',bin_dir/'cryptid')
if str(bin_dir) not in os.environ.get('PATH','').split(os.pathsep):
    print('Add this line to your shell configuration:')
    print('  export PATH='+shlex.quote(str(bin_dir))+':"$PATH"')
print('Try: '+str(bin_dir/'cryptid')+' --help')
PY

