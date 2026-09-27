"""Independent codec boundaries, malformed data, search regressions and CLI contracts."""
import base64
import bz2
import gzip
import lzma
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import time
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'benchmarks'))
from encoders import ENCODERS, caesar
from cryptid import __version__
from cryptid.codecs import decode, MAX_OUTPUT
from cryptid.engine import solve


class CodecBoundaries(unittest.TestCase):
    def outputs(self, data):
        return [t.data for t in decode(data)]

    def test_all_reversible_format_variants(self):
        cipher_names = {'caesar7','rot13','xor42','xorFF','atbash','rot47','reverse','morse'}
        rng = random.Random(24681)
        for name, encoder in ENCODERS.items():
            if name in cipher_names:
                continue
            for size in (4,5,6,7,8,15,16,17,31,32,33,64,129):
                raw = bytes(rng.randrange(32,127) for _ in range(size))
                encoded = encoder(raw)
                # An all-safe URL-form value can have no escaped bytes at all.
                if encoded == raw:
                    continue
                with self.subTest(method=name, size=size):
                    self.assertIn(raw, self.outputs(encoded))

    def test_arbitrary_bytes_roundtrip(self):
        methods = ['base64','base64-url','base32','hex','base85','ascii85','base58',
                   'hex-escapes','octal-escapes','binary','decimal','octal','url',
                   'quoted-printable','gzip','zlib','bzip2','xz']
        rng = random.Random(1871)
        for name in methods:
            for size in (4,5,16,255,256,257):
                raw = bytes(rng.randrange(256) for _ in range(size))
                with self.subTest(method=name, size=size):
                    self.assertIn(raw, self.outputs(ENCODERS[name](raw)))

    def test_base58_leading_zero_bytes(self):
        for zeros in range(1,17):
            raw = b'\0' * zeros + b'hello world'
            with self.subTest(zeros=zeros):
                self.assertIn(raw, self.outputs(ENCODERS['base58'](raw)))

    def test_short_rfc_vectors(self):
        for raw in (b'f', b'fo', b'foo', b'foob', b'fooba', b'foobar'):
            for encoder in (base64.b64encode, base64.b32encode):
                for trim in (False, True):
                    encoded = encoder(raw)
                    if trim: encoded = encoded.rstrip(b'=')
                    # Base64's one-byte unpadded form has only two characters.
                    with self.subTest(raw=raw, method=encoder.__name__, trim=trim):
                        self.assertIn(raw, self.outputs(encoded))

    def test_padding_and_nonzero_pad_bits_rejected(self):
        examples = [('Base64', b'Zh=='), ('Base64', b'Zm9='), ('Base64', b'YQ='),
                    ('Base64', b'YQ==='), ('Base32', b'MZ======'),
                    ('Base32', b'MY='), ('Base32', b'MY=======')]
        for name, data in examples:
            with self.subTest(name=name, data=data):
                self.assertFalse(any(t.name == name for t in decode(data)))

    def test_morse_complete_alphabet(self):
        raw = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789 .,?/-@:='
        self.assertIn(raw, self.outputs(ENCODERS['morse'](raw)))

    def test_morse_unknown_symbols_rejected(self):
        for raw in (b'......', b'... x ...', b'..--..---'):
            with self.subTest(raw=raw):
                self.assertFalse(any(t.name == 'Morse' for t in decode(raw)))

    def test_url_form_without_percent_escapes(self):
        self.assertIn(b'hello world', self.outputs(b'hello+world'))
        self.assertEqual(solve(b'hello+world').best.data, b'hello world')

    def test_url_form_spaces_in_structured_text(self):
        for raw in (b'print("hello world")\n', b'{"message":"hello world"}'):
            with self.subTest(raw=raw):
                self.assertEqual(solve(ENCODERS['url-form'](raw)).best.data, raw)

    def test_unicode_text_bytes(self):
        for data, expected in ((b'\\u00e9', 'é'.encode()), (b'\\U0001f680', '🚀'.encode()),
                               (b'&#233;', 'é'.encode()), (b'&#x1f680;', '🚀'.encode())):
            with self.subTest(data=data):
                self.assertIn(expected, self.outputs(data))

    def test_unicode_surrogates_rejected(self):
        self.assertFalse(any(t.name == 'Unicode escapes' for t in decode(b'\\ud800')))

    def test_all_compression_integrity_checks(self):
        for name in ('gzip','zlib','bzip2','xz'):
            valid = ENCODERS[name](b'flag{complete_compressed_stream}')
            for corrupted in (valid[:-1],valid+b'tail',valid+valid,valid[:8]):
                with self.subTest(method=name, sample=corrupted[:8]):
                    self.assertFalse(any(t.family == 'compression' for t in decode(corrupted)))

    def test_all_compression_output_limits(self):
        raw = b'A' * (MAX_OUTPUT+1)
        for name in ('gzip','zlib','bzip2','xz'):
            with self.subTest(method=name):
                self.assertFalse(any(t.family == 'compression' for t in decode(ENCODERS[name](raw))))

    def test_zlib_window_sizes(self):
        raw = b'flag{every_standard_zlib_window}'
        for size in range(9,16):
            compressor = zlib.compressobj(wbits=size)
            encoded = compressor.compress(raw)+compressor.flush()
            with self.subTest(size=size):
                self.assertIn(raw, self.outputs(encoded))

    def test_invalid_numeric_byte_lists(self):
        for name, data in [('Decimal bytes',b'256 255'),('Octal bytes',b'777 000'),
                           ('Binary',b'0100000'),('Hex',b'0x123'),('Hex byte list',b'0xFF,0xGG')]:
            with self.subTest(name=name):
                self.assertFalse(any(t.name == name for t in decode(data)))


class SearchRegressions(unittest.TestCase):
    def test_affine_wrapper_collision_prefers_readable_body(self):
        from encoders import affine
        raw = b'KAP{decode_the_layers_13d8124080a4}'
        self.assertEqual(solve(affine(raw,3,0)).best.data, raw)

    def test_xor_flag_resembling_quoted_printable(self):
        raw = b'KAP{decode_the_layers_13d8124080a4}'
        encoded = bytes(b ^ 5 for b in raw)
        self.assertIn(b'=47', encoded)
        self.assertEqual(solve(encoded).best.data, raw)

    def test_embedded_flag_requires_readable_context(self):
        from cryptid.scoring import assess
        self.assertEqual(assess(b'Your flag is HTB{inside_the_message}').kind, 'flag')
        self.assertNotEqual(assess(b'Xa5$9!zzfR'*15 + b'HTB{accidental}' + b'J7k%qR_'*15).kind, 'flag')

    def test_mostly_ascii_binary_does_not_enter_text_only_attacks(self):
        from cryptid.ciphers import advanced
        raw = b'The message arrived at the house during the night. ' * 8 + b'\x96'
        # A binary outlier must not reach the ASCII-only Vigenere scorer.
        list(advanced(raw, time.monotonic() + 0.2))

    def test_all_caesar_shifts(self):
        raw = b'HTB{Keep_Case_0123456789}'
        for shift in range(26):
            with self.subTest(shift=shift):
                self.assertEqual(solve(caesar(raw,shift)).best.data,raw)

    def test_all_single_byte_xor_keys(self):
        raw = b'KAP{single_byte_xor_0123456789}'
        for key in range(256):
            with self.subTest(key=key):
                result = solve(bytes(b ^ key for b in raw))
                self.assertEqual(result.best.data,raw)
                self.assertIn(result.status,('already-plaintext','likely-plaintext'))

    def test_repeated_base85_formats(self):
        raw = b'flag{repeated_base85_layers}'
        for method in ('base85','ascii85'):
            for depth in (2,3,5):
                encoded=raw
                for _ in range(depth): encoded=ENCODERS[method](encoded)
                with self.subTest(method=method,depth=depth):
                    self.assertEqual(solve(encoded).best.data,raw)

    def test_reversed_lowercase_base32(self):
        raw = b'HTB{reversed_lowercase_encoding}'
        encoded = base64.b64encode(base64.b32encode(raw).lower()[::-1])
        self.assertEqual(solve(encoded).best.data,raw)

    def test_all_plaintext_bytes_preserved(self):
        for suffix in (b'',b'\n',b'\r\n',b'\t',b'  '):
            raw = b'  flag{keep_the_original_bytes}' + suffix
            with self.subTest(suffix=suffix):
                self.assertEqual(solve(base64.b64encode(raw)).best.data,raw)


class CLIContracts(unittest.TestCase):
    def cli(self,*args,input=None):
        return subprocess.run([sys.executable,str(ROOT/'cryptid.py'),*args],input=input,
                              capture_output=True,timeout=30)

    def test_first_release_and_watermark(self):
        self.assertEqual(__version__,'1.0.0')
        for option in ('--version','--help','--list'):
            with self.subTest(option=option):
                result=self.cli(option)
                self.assertEqual(result.returncode,0)
                self.assertIn(b'1.0.0',result.stdout)
                self.assertIn(b'https://github.com/aadhilfazal',result.stdout)

    def test_top_range_and_ambiguous_sources(self):
        for args in (('--top','0'),('--top','11'),('hello','-f','anything')):
            with self.subTest(args=args):
                self.assertEqual(self.cli(*args).returncode,2)

    def test_output_report_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'same'
            result=self.cli('aGVsbG8gd29ybGQ=','-o',str(path),'--report',str(path))
            self.assertEqual(result.returncode,2)
            self.assertFalse(path.exists())

    def test_symlink_input_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'input'; alias=Path(directory)/'alias'
            path.write_bytes(b'aGVsbG8gd29ybGQ='); alias.symlink_to(path)
            result=self.cli('-f',str(path),'-o',str(alias))
            self.assertEqual(result.returncode,2)
            self.assertEqual(path.read_bytes(),b'aGVsbG8gd29ybGQ=')

    def test_missing_output_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            result=self.cli('aGVsbG8gd29ybGQ=','-o',str(Path(directory)/'absent'/'answer'))
            self.assertEqual(result.returncode,2)

    def test_unresolved_input_does_not_overwrite_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'answer'; path.write_bytes(b'keep this result')
            result=self.cli('-d','-o',str(path),input=b'\0'*48)
            self.assertIn(result.returncode,(1,3))
            self.assertEqual(result.stdout,b'')
            self.assertEqual(path.read_bytes(),b'keep this result')


if __name__ == '__main__':
    unittest.main()
