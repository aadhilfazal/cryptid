"""Known-answer and end-to-end regressions, independent of decoder internals."""
import base64
import gzip
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from cryptid.codecs import decode, MAX_OUTPUT
from cryptid.engine import solve
from cryptid.scoring import preview


class KnownAnswers(unittest.TestCase):
    def test_encoding_vectors(self):
        vectors=[(b'Zg==',b'f'),(b'Zm9vYmFy',b'foobar'),(b'MZXW6YTBOI======',b'foobar'),
                 (b'666f6f626172',b'foobar'),(b'\\x66\\x6f\\x6f',b'foo'),
                 (b'01100110 01101111 01101111',b'foo'),(b'102 111 111',b'foo'),
                 (b'146 157 157',b'foo'),(b'%66%6F%6F',b'foo'),(b'&#102;&#111;&#111;',b'foo'),
                 (b'\\u0066\\u006f\\u006f',b'foo'),(b'=66=6F=6F',b'foo'),
                 (b'.... . .-.. .-.. --- / .-- --- .-. .-.. -..',b'HELLO WORLD')]
        for encoded,expected in vectors:
            with self.subTest(encoded=encoded): self.assertIn(expected,[t.data for t in decode(encoded)])

    def test_caesar_known_answer(self):
        r=solve(b'Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj')
        self.assertEqual(r.best.data,b'The quick brown fox jumps over the lazy dog')

    def test_rot13_known_answer(self):
        self.assertEqual(solve(b'synt{uryyb_jbeyq}').best.data,b'flag{hello_world}')

    def test_original_mixed_examples(self):
        for name in ('mixed_layers.txt','xor_layers.txt','base64_repeated.txt'):
            with self.subTest(name=name):
                p=ROOT/'examples'/name
                r=solve(p.read_bytes())
                self.assertEqual(r.best.data,p.with_name(p.name+'.expected').read_bytes())
                self.assertEqual(r.status,'likely-plaintext')

    def test_plaintext_is_not_modified(self):
        for data in (b'hello world\n',b'  The message contains spaces at both ends.  ',b'KAP{keep_My_CASE}'):
            with self.subTest(data=data):
                r=solve(data);self.assertEqual(r.best.data,data);self.assertFalse(r.best.steps)

    def test_repeated_layers(self):
        for count in (3,5,10,16):
            raw=b'HTB{repeated_layers}'; encoded=raw
            for _ in range(count): encoded=base64.b64encode(encoded)
            with self.subTest(count=count):
                r=solve(encoded);self.assertEqual(r.best.data,raw)
                self.assertEqual(len(r.best.steps),count)

    def test_decompression_limits(self):
        bomb=gzip.compress(b'A'*(MAX_OUTPUT+1))
        self.assertFalse(any(t.family=='compression' for t in decode(bomb)))

    def test_compression_integrity(self):
        raw=gzip.compress(b'flag{checksum}')
        self.assertFalse(any(t.family=='compression' for t in decode(raw[:-1])))
        self.assertFalse(any(t.family=='compression' for t in decode(raw+b'trailing')))

    def test_binary_signature_is_not_plaintext(self):
        data=b'\x89PNG\r\n\x1a\n'+bytes(range(32))
        r=solve(base64.b64encode(data))
        self.assertEqual(r.best.data,data);self.assertEqual(r.status,'decoded-binary')

    def test_terminal_controls_escaped(self):
        self.assertNotIn('\x1b',preview(b'hello\x1b[2Jworld'))

    def test_percent_syntax_can_be_rot47(self):
        raw=b'The server returned a message after the last packet arrived.'
        encoded=bytes(33+(b-33+47)%94 if 33<=b<=126 else b for b in raw)
        self.assertTrue(encoded.startswith(b'%96'))
        self.assertEqual(solve(encoded).best.data,raw)

    def test_reversed_base64_can_resemble_quoted_printable(self):
        raw=b'Please bring the blue notebook to the old station at midnight.'
        encoded=base64.b32encode(base64.b64encode(raw)[::-1])
        r=solve(encoded)
        self.assertEqual(r.best.data,raw)
        self.assertEqual([s.name for s in r.best.steps],['Base32','Reverse','Base64'])

    def test_invalid_utf8_is_not_plaintext(self):
        from cryptid.scoring import assess
        self.assertEqual(assess(b'\x96 server returned a message after the last packet arrived.').kind,'unknown')


class CLI(unittest.TestCase):
    def run_cli(self,*args,input=None):
        return subprocess.run([sys.executable,str(ROOT/'cryptid.py'),*args],input=input,capture_output=True,timeout=20)

    def test_raw_output_exact(self):
        for raw in (b'hello world',b'hello world\n',b'  hello world  '):
            p=self.run_cli('-d',input=base64.b64encode(raw))
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertEqual(p.stdout,raw)
            self.assertIn(b'https://github.com/aadhilfazal',p.stderr)

    def test_output_and_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'answer';report=Path(tmp)/'trace'
            p=self.run_cli('SFRCe2ZpbGVfb3V0cHV0fQ==','-o',str(out),'--report',str(report))
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertEqual(out.read_bytes(),b'HTB{file_output}')
            self.assertIn('Base64',report.read_text())
            self.assertIn('aadhilfazal',report.read_text())

    def test_removed_switches_rejected(self):
        for flag in ('--time','--timeout','--no-color','--max-depth','--only','--skip','--contains','--recipe','--save-steps','--json'):
            with self.subTest(flag=flag): self.assertEqual(self.run_cli(flag).returncode,2)

    def test_empty_and_missing_input(self):
        self.assertEqual(self.run_cli(input=b'').returncode,2)
        self.assertEqual(self.run_cli('-f','/no/such/cryptid/file').returncode,2)

    def test_collision_protection(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'input';p.write_bytes(b'YQ==')
            r=self.run_cli('-f',str(p),'-o',str(p))
            self.assertEqual(r.returncode,2);self.assertEqual(p.read_bytes(),b'YQ==')

    def test_large_input_rejected(self):
        self.assertEqual(self.run_cli(input=b'A'*(1024*1024+1)).returncode,2)


if __name__=='__main__': unittest.main()
