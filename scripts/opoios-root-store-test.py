#!/usr/bin/env python3
"""Tests of scripts/opoios-root-store.py (OPOIOS stage 4 step 4): build, verify and the reference reader.

    python3 scripts/opoios-root-store-test.py

Synthetic images signed like kits/VerifiedRoot tools/manifest.py does (a throwaway RSA-3072 key from openssl). LZFSE: macOS
libcompression or liblzfse when present; otherwise a stand-in codec (raw deflate) exercises the same format paths and the
real LZFSE is covered where it exists (the CI runs this file on macOS before it builds the store).
"""
import errno
import hashlib
import importlib.util
import os
import random
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('opoios_root_store', HERE / 'opoios-root-store.py')
S = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = S          # spawned workers unpickle opoios_root_store.span_job (they re-run this file first)
_spec.loader.exec_module(S)
BLOCK, CHUNK = S.BLOCK, S.CHUNK
OPENSSL = os.environ.get('OPENSSL', 'openssl')     # OpenSSL 3 (the CI sets it; macOS's LibreSSL lacks -quiet)


class Deflate:
    """Stand-in codec when no LZFSE library exists here."""
    name = 'raw deflate (stand-in)'

    def encode(self, data):
        c = zlib.compressobj(6, zlib.DEFLATED, -15)
        blob = c.compress(data) + c.flush()
        return blob if len(blob) < len(data) else b''

    def decode(self, blob, n):
        d = zlib.decompressobj(-15)
        return d.decompress(blob, n + 1)


try:
    S.Lzfse()
except (RuntimeError, OSError):
    S.Lzfse = Deflate        # here and in spawned workers, which run this file again before they unpickle a task


def codec():
    return S.Lzfse()


class Signer:
    def __init__(self, d):
        self.key, self.pub = d / 'key.pem', d / 'pub.pem'
        subprocess.run([OPENSSL, 'genpkey', '-quiet', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072',
                        '-out', str(self.key)], check=True)
        subprocess.run([OPENSSL, 'pkey', '-in', str(self.key), '-pubout', '-out', str(self.pub)], check=True)
        line = subprocess.check_output([OPENSSL, 'rsa', '-pubin', '-in', str(self.pub), '-modulus', '-noout'], text=True)
        self.anchor = b'VROOTKEY' + bytes.fromhex(line.strip().split('=', 1)[1]) + b'\x01\x00\x01'
        self.d = d

    def manifest(self, image, volume=None):
        data = Path(image).read_bytes()
        hashes = b''.join(hashlib.sha256(data[i:i + BLOCK]).digest() for i in range(0, len(data), BLOCK))
        header = struct.pack('<8s4I2Q16s32s32s32sQ', b'VROOT01\0', 1, 160, 4096, 0, len(data), len(hashes) // 32,
                             (volume or uuid.uuid4()).bytes, hashlib.sha256(data).digest(), hashlib.sha256(hashes).digest(),
                             hashlib.sha256(self.anchor).digest(), 1)
        (self.d / 'h.bin').write_bytes(header)
        sig = subprocess.check_output([OPENSSL, 'dgst', '-sha256', '-sign', str(self.key), str(self.d / 'h.bin')])
        return S.Manifest(header + sig, self.anchor)


def make_image(path, layout, seed=1):
    """layout: list of chunk kinds: 'random', 'text', 'zero', 'mixed'; the image ends with tail_bytes extra."""
    rng = random.Random(seed)
    out = bytearray()
    for kind in layout:
        if kind == 'random':
            out += rng.randbytes(CHUNK)
        elif kind == 'text':
            line = b'OPOIOS stage 4 RAM root store test line %d\n' % rng.randrange(1000)
            out += (line * (CHUNK // len(line) + 1))[:CHUNK]
        elif kind == 'zero':
            out += bytes(CHUNK)
        elif kind == 'mixed':      # zero, random and text blocks
            for i in range(CHUNK // BLOCK):
                out += bytes(BLOCK) if i % 3 == 0 else rng.randbytes(BLOCK) if i % 3 == 1 else b'x' * BLOCK
        elif isinstance(kind, int):  # a short tail: kind bytes of text
            out += (b'tail-' * (kind // 5 + 1))[:kind]
    Path(path).write_bytes(bytes(out))
    return bytes(out)


class StoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.d = Path(cls.tmp.name)
        cls.signer = Signer(cls.d)
        cls.codec = codec()
        print(f'codec: {cls.codec.name}', file=sys.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def build_two(self, mask_os=None, mask_sys=None, name='store.bin'):
        # OS: random, text, zero, mixed, text + a 5000-byte tail (a partial chunk with a partial block)
        os_img = make_image(self.d / 'os.img', ['random', 'text', 'zero', 'mixed', 'text', 5000], seed=2)
        sys_img = make_image(self.d / 'sys.img', ['text', 'random', 'text'], seed=3)
        m_os = self.signer.manifest(self.d / 'os.img', uuid.UUID(int=1))
        m_sys = self.signer.manifest(self.d / 'sys.img', uuid.UUID(int=2))
        n_os, n_sys = (len(os_img) + BLOCK - 1) // BLOCK, (len(sys_img) + BLOCK - 1) // BLOCK
        w = [S.Window('OS', self.d / 'os.img', m_os, mask_os or bytes(n_os)),
             S.Window('SystemOS', self.d / 'sys.img', m_sys, mask_sys or bytes(n_sys))]
        records, size = S.build(w, self.d / name, jobs=0, codec=self.codec, log=lambda *a: None)
        return os_img, sys_img, records, size

    def anchors(self):
        return {'OS': self.signer.anchor, 'SystemOS': self.signer.anchor}

    def open_store(self, path, anchors, codec):
        store = S.Store(path, anchors, codec)
        self.addCleanup(store.close)
        return store

    def test_roundtrip_and_kinds(self):
        os_img, sys_img, records, size = self.build_two()
        self.assertEqual(size, (self.d / 'store.bin').stat().st_size)
        self.assertEqual(size % 4096, 0)
        r_os = records[0]
        self.assertEqual(r_os['chunk_count'], 6)
        self.assertEqual((r_os['zero_chunks'], r_os['raw_chunks'], r_os['lzfse_chunks']), (1, 1, 4))
        self.assertEqual(r_os['dropped_blocks'], 0)
        store = self.open_store(self.d / 'store.bin', self.anchors(), self.codec)
        for name, img in (('OS', os_img), ('SystemOS', sys_img)):
            for b in range((len(img) + BLOCK - 1) // BLOCK):
                self.assertEqual(store.read_block(name, b), img[b * BLOCK:(b + 1) * BLOCK], f'{name} block {b}')
        out = S.verify(self.d / 'store.bin', self.anchors(), jobs=0, codec=self.codec, log=lambda *a: None)
        self.assertEqual(out['OS']['present'], (len(os_img) + BLOCK - 1) // BLOCK)

    def test_dropped_blocks(self):
        n_os = (5 * CHUNK + 5000 + BLOCK - 1) // BLOCK
        mask = bytearray(n_os)
        drop = [0, 1, 17, 30, 31, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, n_os - 1]
        for b in drop:                      # in random, text, zero chunks; all of chunk 3 (mixed); the tail block
            mask[b] = 1
        os_img, _, records, _ = self.build_two(mask_os=bytes(mask))
        self.assertEqual(records[0]['dropped_blocks'], len(drop))
        self.assertEqual(records[0]['zero_chunks'], 2)          # the zero chunk and the all-dropped mixed chunk
        store = self.open_store(self.d / 'store.bin', self.anchors(), self.codec)
        for b in range(n_os):
            if mask[b]:
                with self.assertRaises(OSError) as e:
                    store.read_block('OS', b)
                self.assertEqual(e.exception.errno, errno.EIO)
            else:
                self.assertEqual(store.read_block('OS', b), os_img[b * BLOCK:(b + 1) * BLOCK])
        S.verify(self.d / 'store.bin', self.anchors(), codec=self.codec, log=lambda *a: None)

    def test_image_not_the_signed_one(self):
        make_image(self.d / 'x.img', ['text', 'random'], seed=5)
        m = self.signer.manifest(self.d / 'x.img')
        data = bytearray((self.d / 'x.img').read_bytes())
        data[CHUNK + 100] ^= 1
        (self.d / 'x.img').write_bytes(bytes(data))
        w = [S.Window('OS', self.d / 'x.img', m, bytes(len(data) // BLOCK))]
        with self.assertRaisesRegex(ValueError, 'not the one the signed manifest covers'):
            S.build(w, self.d / 'x.bin', codec=self.codec, log=lambda *a: None)

    def test_damaged_data_is_eio_only_there(self):
        os_img, _, records, _ = self.build_two(name='bad.bin')
        store = self.open_store(self.d / 'bad.bin', self.anchors(), self.codec)
        off, stored, present, kind = S.ENTRY.unpack_from(store.windows['OS']['table'], 1 * S.ENTRY.size)   # text chunk
        self.assertEqual(kind, S.KIND_LZFSE)
        data = bytearray((self.d / 'bad.bin').read_bytes())
        data[store.windows['OS']['data_offset'] + off + stored // 2] ^= 0x40
        (self.d / 'bad.bin').write_bytes(bytes(data))
        store = self.open_store(self.d / 'bad.bin', self.anchors(), self.codec)
        failed = 0
        for b in range(16, 32):
            try:
                self.assertEqual(store.read_block('OS', b), os_img[b * BLOCK:(b + 1) * BLOCK])
            except OSError as e:
                self.assertEqual(e.errno, errno.EIO)
                failed += 1
        self.assertGreater(failed, 0)
        self.assertEqual(store.read_block('OS', 0), os_img[:BLOCK])           # other chunks still read
        with self.assertRaises((OSError, ValueError)):
            S.verify(self.d / 'bad.bin', self.anchors(), codec=self.codec, log=lambda *a: None)

    def test_forged_present_bit_is_eio(self):
        n_os = (5 * CHUNK + 5000 + BLOCK - 1) // BLOCK
        mask = bytearray(n_os)
        mask[5] = 1                          # a random (nonzero) block, dropped
        self.build_two(mask_os=bytes(mask), name='forge.bin')
        store = self.open_store(self.d / 'forge.bin', self.anchors(), self.codec)
        w = store.windows['OS']
        off, stored, present, kind = S.ENTRY.unpack_from(w['table'], 0)
        w['table'] = S.ENTRY.pack(off, stored, present | 1 << 5, kind) + w['table'][S.ENTRY.size:]
        with self.assertRaises(OSError) as e:
            store.read_block('OS', 5)          # the stored zeros do not match the signed hash
        self.assertEqual(e.exception.errno, errno.EIO)

    def test_wrong_key_and_header(self):
        self.build_two(name='key.bin')
        (self.d / 'other').mkdir(exist_ok=True)
        other = Signer(self.d / 'other')
        with self.assertRaisesRegex(ValueError, 'key anchor'):
            S.Store(self.d / 'key.bin', {'OS': other.anchor, 'SystemOS': other.anchor}, self.codec)
        data = bytearray((self.d / 'key.bin').read_bytes())
        data[64 + 40] ^= 1                    # block count of window 0
        (self.d / 'key.bin').write_bytes(bytes(data))
        with self.assertRaisesRegex(ValueError, 'header checksum'):
            S.Store(self.d / 'key.bin', self.anchors(), self.codec)

    def test_multiple_spans(self):
        old = S.SPAN
        try:
            S.SPAN = 2 * CHUNK               # the image in three tasks; the store must be the same
            self.build_two(name='spans.bin')
        finally:
            S.SPAN = old
        self.build_two(name='one.bin')
        self.assertEqual((self.d / 'spans.bin').read_bytes(), (self.d / 'one.bin').read_bytes())

    def test_parallel_build_and_verify(self):
        old = S.SPAN
        try:
            S.SPAN = 2 * CHUNK
            self.build_two(name='serial.bin')
            os_img = (self.d / 'os.img').read_bytes()
            sys_img = (self.d / 'sys.img').read_bytes()
            w = [S.Window('OS', self.d / 'os.img', self.signer.manifest(self.d / 'os.img', uuid.UUID(int=1)),
                          bytes((len(os_img) + BLOCK - 1) // BLOCK)),
                 S.Window('SystemOS', self.d / 'sys.img', self.signer.manifest(self.d / 'sys.img', uuid.UUID(int=2)),
                          bytes((len(sys_img) + BLOCK - 1) // BLOCK))]
            S.build(w, self.d / 'parallel.bin', jobs=2, log=lambda *a: None)     # three tasks over two workers
        finally:
            S.SPAN = old
        self.assertEqual((self.d / 'parallel.bin').read_bytes(), (self.d / 'serial.bin').read_bytes())
        S.verify(self.d / 'parallel.bin', self.anchors(), jobs=2, log=lambda *a: None)

    def test_groups(self):
        groups = S.store_groups()
        drop = S.default_drop(groups)
        for n in ('ane', 'staged-apps', 'dyld-symbols', 'watch-faces', 'tts-maui', 'camera-models'):
            self.assertIn(n, drop)
        for n in ('ml-models', 'vision-resources'):
            self.assertNotIn(n, drop)
        g = {x['name']: x for x in groups}
        bm = S.BM
        self.assertTrue(bm.in_group(g['watch-faces'], '/System/Library/NanoTimeKit/FaceBundles/Astro.bundle/x.car'))
        self.assertFalse(bm.in_group(g['watch-faces'], '/System/Library/NanoTimeKit/NanoTimeKit.framework/x'))
        self.assertTrue(bm.in_group(g['camera-models'], '/System/Library/CoreServices/RawCamera.bundle/RawSFD/bayer_weight.bin'))
        self.assertFalse(bm.in_group(g['camera-models'], '/System/Library/CoreServices/RawCamera.bundle/RawCamera'))
        self.assertTrue(bm.in_group(g['linguistic'], '/System/Library/LinguisticData/de/x.dat'))
        self.assertFalse(bm.in_group(g['linguistic'], '/System/Library/LinguisticData/ru/x.dat'))

    def test_real_policy_signatures(self):
        policy = HERE / 'policies' / 'ios-27.0.1-24A446'
        for name, size in (('OS', 10223616000), ('SystemOS', 6023020544)):
            m = S.Manifest.load(policy, name)
            self.assertEqual(m.image_bytes, size)


if __name__ == '__main__':
    unittest.main(verbosity=2)
