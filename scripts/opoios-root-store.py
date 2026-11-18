#!/usr/bin/env python3
"""OPOIOS: the RAM root store (stage 4 path 1, step 4): original iOS root images minus trimmed files, LZFSE chunks.

    python3 scripts/opoios-root-store.py build --policy DIR --out DIR [--drop GROUP ...] [--group NAME=GLOB ...]
                                               [--budget BYTES] [--jobs N] OS=IMAGE SystemOS=IMAGE
    python3 scripts/opoios-root-store.py verify --policy DIR [--jobs N] STORE

The phone receives the store over USB in UEFI (OPOIOS XueyingUsbRamDxe) into the RAM above the XNU window; the kernel serves
the windows (OS, SystemOS) as block devices from it (step 5). Nothing of the APFS images is rebuilt: a window is the original
disk image byte for byte, except that blocks used only by dropped files are not kept (reading one is EIO), and every block the
kernel hands out is first checked against the image's signed VerifiedRoot manifest (kits/VerifiedRoot). The store is
therefore not trusted by the kernel; a damaged or forged table can only make reads fail.

Store format OPROOT01, version 1. Little-endian; section offsets are store offsets, multiples of 4096.

  header, 4096 bytes at offset 0
     0  magic 'OPROOT01'            8  u32 version 1         12  u32 header bytes 4096
    16  u32 window count (1..4)    20  u32 chunk bytes 65536  24  u64 store bytes          32  u64 flags 0
    64 + 192 * i: window i
         0  name[16] ('OS', 'SystemOS'; NUL padded)          16  volume UUID[16] (copy of the manifest's)
        32  u64 image bytes   40  u64 block count (4 KiB)    48  u64 chunk count
        56  u64 manifest offset  64  u64 manifest bytes: the VerifiedRoot envelope as vr_open takes it
                                     (160-byte header, 384-byte RSA-3072 signature, block count * 32 bytes of SHA-256)
        72  u64 table offset     80  u64 table bytes: chunk count entries of 16 bytes
        88  u64 data offset      96  u64 data bytes
       104  u64 present blocks  112  u64 dropped blocks  120  u64 zero, raw, LZFSE chunks (3 x u64)
       144  table SHA-256[32]
  4064  header SHA-256[32] of bytes 0..4063
  then the manifests and chunk tables of all windows, then the data of window 0, window 1, ...

  chunk entry, 16 bytes: u64 offset in the window's data, u32 stored bytes, u16 present, u8 kind, u8 0
     present: bit i set = block i of the chunk can be read; bits past the end of the image are clear
     kind 0 zero: nothing stored (stored bytes 0), the chunk reads as zeros
     kind 1 raw: the chunk as it is      kind 2 LZFSE: decodes to exactly the chunk length
  The chunk length is min(chunk bytes, image bytes - index * chunk bytes). Dropped blocks inside a stored chunk are zeros.

  Reading block b of a window: entry = table[b * 4096 // 65536], bit = b % 16. Bit clear: EIO. Otherwise decode the chunk,
  take the block, vr_verify_block it against the manifest that vr_open authenticated with the key compiled into the kernel.

Trim groups come from scripts/opoios-root-blockmap.py (the same APFS block map as the stage 4 measurement): a file is dropped
when every path that names it matches a dropped group; a block is dropped when no kept file uses it. Metadata, the integrity
tree and free space are always kept. `build` checks every image against its signed manifest (the hash table of the image must
be the one the RSA signature covers) and refuses a store above --budget. `verify` decodes every chunk of a store and checks
every present block against the manifest, like the kernel will.

LZFSE: macOS libcompression, elsewhere the reference liblzfse (apt liblzfse-dev). Outputs: store.bin, store.json (sizes and
digests), report.txt (counts per group and the dropped paths; names and sizes only), summary.md.
"""
import argparse
import ctypes
import ctypes.util
import errno
import hashlib
import importlib.util
import json
import multiprocessing
import os
import struct
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('opoios_root_blockmap', HERE / 'opoios-root-blockmap.py')
BM = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(BM)

MAGIC = b'OPROOT01'
VERSION = 1
HEADER_BYTES = 4096
BLOCK = 4096
CHUNK = 65536
PER = CHUNK // BLOCK                       # 16 blocks: the present mask is a u16
WINDOW = struct.Struct('<16s16s3Q2Q2Q2Q2Q3Q32s16x')
ENTRY = struct.Struct('<QIHBx')
HEAD = struct.Struct('<8sIIIIQQ24x')
KIND_ZERO, KIND_RAW, KIND_LZFSE = 0, 1, 2
MAX_WINDOWS = 4
VR_HEADER, VR_SIGNATURE, VR_KEY = 160, 384, 395
SPAN = 256 * BM.MIB                        # one worker task: 4096 chunks
# Proven capacity of the store in phone RAM: the region above the XNU window minus the descriptor page and the ABL payload of
# the stage 3 image (OPOIOS run 3-2, 2026-11-18). A smaller stage 4 payload leaves more room; build to the proven one.
DEFAULT_BUDGET = 8272932864
# Default trim of the store: the default groups of the block map and the store's extra groups.
STORE_EXTRA = ('watch-faces', 'tts-maui', 'camera-models')
assert WINDOW.size == 192 and ENTRY.size == 16 and HEAD.size == 64 and CHUNK % BLOCK == 0 and PER <= 16


def align(n, to=4096):
    return (n + to - 1) // to * to


# ------------------------------------------------------------------------------------------------------------------ LZFSE

class Lzfse:
    """encode(data) -> blob (b'' when it does not get smaller); decode(blob, n) -> bytes."""

    def __init__(self):
        if sys.platform == 'darwin':
            lib = ctypes.CDLL(ctypes.util.find_library('compression') or '/usr/lib/libcompression.dylib')
            lib.compression_encode_buffer.restype = lib.compression_decode_buffer.restype = ctypes.c_size_t
            lib.compression_encode_buffer.argtypes = lib.compression_decode_buffer.argtypes = [
                ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_int]
            lib.compression_encode_scratch_buffer_size.restype = ctypes.c_size_t
            lib.compression_decode_scratch_buffer_size.restype = ctypes.c_size_t
            lib.compression_encode_scratch_buffer_size.argtypes = lib.compression_decode_scratch_buffer_size.argtypes = [
                ctypes.c_int]
            code = 0x801                                   # COMPRESSION_LZFSE
            enc = ctypes.create_string_buffer(lib.compression_encode_scratch_buffer_size(code) or 1)
            dec = ctypes.create_string_buffer(lib.compression_decode_scratch_buffer_size(code) or 1)
            self._enc = lambda dst, n, src, m: lib.compression_encode_buffer(dst, n, src, m, enc, code)
            self._dec = lambda dst, n, src, m: lib.compression_decode_buffer(dst, n, src, m, dec, code)
            self.name = 'LZFSE (libcompression)'
        else:
            # OPOIOS_LZFSE_LIB: a liblzfse built from package/lzfse (scripts/check-opoios-root-store.py does).
            path = os.environ.get('OPOIOS_LZFSE_LIB') or ctypes.util.find_library('lzfse')
            if not path:
                raise RuntimeError('no LZFSE encoder: macOS libcompression or the reference liblzfse (apt liblzfse-dev)')
            lib = ctypes.CDLL(path)
            lib.lzfse_encode_scratch_size.restype = lib.lzfse_decode_scratch_size.restype = ctypes.c_size_t
            lib.lzfse_encode_buffer.restype = lib.lzfse_decode_buffer.restype = ctypes.c_size_t
            lib.lzfse_encode_buffer.argtypes = lib.lzfse_decode_buffer.argtypes = [
                ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
            enc = ctypes.create_string_buffer(lib.lzfse_encode_scratch_size() or 1)
            dec = ctypes.create_string_buffer(lib.lzfse_decode_scratch_size() or 1)
            self._enc = lambda dst, n, src, m: lib.lzfse_encode_buffer(dst, n, src, m, enc)
            self._dec = lambda dst, n, src, m: lib.lzfse_decode_buffer(dst, n, src, m, dec)
            self.name = 'LZFSE (liblzfse)'
        self._out = ctypes.create_string_buffer(CHUNK * 2)

    def encode(self, data):
        n = self._enc(self._out, len(data), data, len(data))     # at most len(data): bigger is useless here
        return ctypes.string_at(self._out, n) if 0 < n < len(data) else b''

    def decode(self, blob, n):
        dst = ctypes.create_string_buffer(n + 1)                  # one spare byte: an over-long stream shows as n + 1
        got = self._dec(dst, n + 1, blob, len(blob))
        return ctypes.string_at(dst, got)


# ---------------------------------------------------------------------------------------------------------- VerifiedRoot

DIGEST_INFO_SHA256 = bytes.fromhex('3031300d060960864801650304020105000420')


def rsa_verify(anchor, message, signature):
    """RSA-3072 PKCS#1 v1.5 SHA-256 against a VerifiedRoot key anchor ('VROOTKEY', modulus, exponent 65537)."""
    if len(anchor) != VR_KEY or anchor[:8] != b'VROOTKEY' or anchor[392:] != b'\x01\x00\x01' or len(signature) != 384:
        return False
    n = int.from_bytes(anchor[8:392], 'big')
    s = int.from_bytes(signature, 'big')
    if s >= n:
        return False
    em = pow(s, 65537, n).to_bytes(384, 'big')
    t = DIGEST_INFO_SHA256 + hashlib.sha256(message).digest()
    return em == b'\x00\x01' + b'\xff' * (384 - 3 - len(t)) + b'\x00' + t


class Manifest:
    """The signed 544-byte VerifiedRoot header of an original image, checked against its key anchor."""

    def __init__(self, header, anchor):
        if len(header) != VR_HEADER + VR_SIGNATURE:
            raise ValueError('manifest header is not 544 bytes')
        magic, version, size, block, zero, image_bytes, count = struct.unpack_from('<8s4I2Q', header)
        if (magic, version, size, block, zero) != (b'VROOT01\0', 1, VR_HEADER, BLOCK, 0):
            raise ValueError('not a VerifiedRoot version 1 header')
        if not image_bytes or count != (image_bytes + BLOCK - 1) // BLOCK:
            raise ValueError('manifest block count does not match its image size')
        if hashlib.sha256(anchor).digest() != header[120:152]:
            raise ValueError('key anchor is not the one the manifest names')
        if not rsa_verify(anchor, header[:VR_HEADER], header[VR_HEADER:]):
            raise ValueError('manifest signature does not verify with its key')
        self.header, self.anchor = bytes(header), bytes(anchor)
        self.image_bytes, self.block_count = image_bytes, count
        self.volume_uuid = header[40:56]
        self.image_sha256, self.table_sha256 = header[56:88], header[88:120]
        self.generation = struct.unpack_from('<Q', header, 152)[0]

    @classmethod
    def load(cls, policy, name):
        d = Path(policy) / name
        return cls((d / 'manifest.header.bin').read_bytes(), (d / 'trusted-key.bin').read_bytes())


# ------------------------------------------------------------------------------------------------------------- trimming

def store_groups(extra=()):
    return BM.group_matchers(list(extra))


def default_drop(groups):
    return [g['name'] for g in groups if g['default']] + [n for n in STORE_EXTRA if any(g['name'] == n for g in groups)]


def dropped_blocks(image, groups, drop):
    """0/1 bytes per 4 KiB block (1 = dropped), dropped paths, per-group file counts, report lines."""
    size = Path(image).stat().st_size
    total = (size + BLOCK - 1) // BLOCK
    drop = set(drop)
    nx = BM.Container(image)
    used, kept = bytearray(total), bytearray(total)
    paths_out, files, report = [], {n: 0 for n in drop}, []
    for index in range(len(nx.fs_oids)):
        volume = BM.Volume(nx, index)
        volume.load()
        by_inode = {}
        for path, oid in volume.files():
            by_inode.setdefault(oid, []).append(path)
        dropped_here = 0
        for oid, paths in by_inode.items():
            extents = list(volume.inode_extents(oid))
            BM.mark(used, extents, total)
            member = {g['name'] for g in groups if g['name'] in drop and all(BM.in_group(g, p) for p in paths)}
            if member:
                dropped_here += 1
                paths_out.extend(sorted(paths))
                for n in member:
                    files[n] += 1
            else:
                BM.mark(kept, extents, total)
        report.append(f'  volume [{index}] "{volume.name}" sealed {volume.sealed}: {len(by_inode)} files, '
                      f'{dropped_here} dropped')
    mask = BM.andnot(bytes(used), bytes(kept))
    return mask, paths_out, files, report


# ----------------------------------------------------------------------------------------------------------------- build

_job = {}


def _worker_init(image, mask, codec=None):
    _job['image'], _job['mask'] = image, mask
    _job['codec'] = codec or Lzfse()


def chunk_record(piece, first_block, mask, codec, image_blocks):
    """(kind, present, blob) of one chunk. piece: the chunk's bytes (the last chunk may be short)."""
    zero = bytes(BLOCK)
    blocks = (len(piece) + BLOCK - 1) // BLOCK
    present, body, nonzero = 0, [], False
    for i in range(blocks):
        b = first_block + i
        data = piece[i * BLOCK:(i + 1) * BLOCK]
        if b < image_blocks and not (b < len(mask) and mask[b]):
            present |= 1 << i
            body.append(data)
            nonzero = nonzero or data != zero[:len(data)]
        else:
            body.append(zero[:len(data)])
    if not nonzero:
        return KIND_ZERO, present, b''
    body = b''.join(body)
    blob = codec.encode(body)
    if blob and len(blob) < len(body):
        return KIND_LZFSE, present, blob
    return KIND_RAW, present, body


def span_job(task):
    """One span of the image, task = (start, bytes), both multiples of CHUNK: block hashes, chunk records."""
    start, size = task
    chunk = CHUNK
    with open(_job['image'], 'rb') as f:
        f.seek(start)
        data = f.read(size)
    image_blocks = (os.path.getsize(_job['image']) + BLOCK - 1) // BLOCK
    hashes = b''.join(hashlib.sha256(data[i:i + BLOCK]).digest() for i in range(0, len(data), BLOCK))
    records = [chunk_record(data[at:at + chunk], (start + at) // BLOCK, _job['mask'], _job['codec'], image_blocks)
               for at in range(0, len(data), chunk)]
    return hashes, records


class Window:
    def __init__(self, name, image, manifest, mask):
        self.name, self.image, self.manifest, self.mask = name, Path(image), manifest, mask
        self.chunk_count = (manifest.image_bytes + CHUNK - 1) // CHUNK
        self.manifest_bytes = VR_HEADER + VR_SIGNATURE + manifest.block_count * 32
        self.table_bytes = self.chunk_count * ENTRY.size


def build(windows, out, jobs=0, codec=None, log=print):
    """windows: [Window]; writes the store to out; returns the window records (dicts). jobs <= 1: in this process
    (codec may then be any object with encode/decode, for tests)."""
    if not 1 <= len(windows) <= MAX_WINDOWS:
        raise ValueError(f'1 to {MAX_WINDOWS} windows')
    for w in windows:
        if len(w.name.encode()) > 16:
            raise ValueError(f'window name {w.name!r} is longer than 16 bytes')
        if w.image.stat().st_size != w.manifest.image_bytes:
            raise ValueError(f'{w.name}: image is {w.image.stat().st_size} bytes, the manifest says {w.manifest.image_bytes}')
    at = HEADER_BYTES
    for w in windows:
        w.manifest_offset, at = at, align(at + w.manifest_bytes)
        w.table_offset, at = at, align(at + w.table_bytes)
    records = []
    with open(out, 'w+b') as f:
        f.truncate(at)
        for w in windows:
            w.data_offset = at
            f.seek(w.manifest_offset)
            f.write(w.manifest.header)
            table, table_hash = bytearray(), hashlib.sha256()
            stats = dict(present=0, dropped=0, kinds=[0, 0, 0])
            data_at, block = 0, 0
            t0 = time.time()
            starts = [(s, SPAN) for s in range(0, w.manifest.image_bytes, SPAN)]
            if jobs and jobs > 1:
                pool = multiprocessing.get_context('spawn').Pool(jobs, _worker_init, (str(w.image), w.mask))
                results = pool.imap(span_job, starts)
            else:
                pool = None
                _worker_init(str(w.image), w.mask, codec)
                results = (span_job(s) for s in starts)
            try:
                for hashes, chunk_records in results:
                    f.seek(w.manifest_offset + VR_HEADER + VR_SIGNATURE + block * 32)
                    f.write(hashes)
                    table_hash.update(hashes)
                    block += len(hashes) // 32
                    f.seek(w.data_offset + data_at)
                    for kind, present, blob in chunk_records:
                        table += ENTRY.pack(data_at, len(blob), present, kind)
                        f.write(blob)
                        data_at += len(blob)
                        stats['kinds'][kind] += 1
                        stats['present'] += bin(present).count('1')
            finally:
                if pool:
                    pool.close()
                    pool.join()
            if block != w.manifest.block_count or table_hash.digest() != w.manifest.table_sha256:
                raise ValueError(f'{w.name}: the image is not the one the signed manifest covers (block hashes differ)')
            stats['dropped'] = w.manifest.block_count - stats['present']
            f.seek(w.table_offset)
            f.write(table)
            w.data_bytes = data_at
            at = align(w.data_offset + data_at)
            rec = dict(name=w.name, volume_uuid=w.manifest.volume_uuid.hex(), image_bytes=w.manifest.image_bytes,
                       block_count=w.manifest.block_count, chunk_count=w.chunk_count,
                       manifest_offset=w.manifest_offset, manifest_bytes=w.manifest_bytes,
                       table_offset=w.table_offset, table_bytes=w.table_bytes, table_sha256=hashlib.sha256(table).hexdigest(),
                       data_offset=w.data_offset, data_bytes=data_at, present_blocks=stats['present'],
                       dropped_blocks=stats['dropped'], zero_chunks=stats['kinds'][0], raw_chunks=stats['kinds'][1],
                       lzfse_chunks=stats['kinds'][2], seconds=round(time.time() - t0, 1))
            records.append(rec)
            log(f'{w.name}: {rec["chunk_count"]} chunks (zero {rec["zero_chunks"]}, raw {rec["raw_chunks"]}, '
                f'LZFSE {rec["lzfse_chunks"]}), data {data_at / BM.GIB:.3f} GiB, dropped blocks {stats["dropped"]} '
                f'({stats["dropped"] * BLOCK / BM.GIB:.3f} GiB), block hashes match the signed manifest, {rec["seconds"]} s')
        store_bytes = at
        f.truncate(store_bytes)
        header = bytearray(HEADER_BYTES)
        HEAD.pack_into(header, 0, MAGIC, VERSION, HEADER_BYTES, len(windows), CHUNK, store_bytes, 0)
        for i, (w, rec) in enumerate(zip(windows, records)):
            WINDOW.pack_into(header, 64 + WINDOW.size * i, w.name.encode(), w.manifest.volume_uuid,
                             w.manifest.image_bytes, w.manifest.block_count, w.chunk_count,
                             w.manifest_offset, w.manifest_bytes, w.table_offset, w.table_bytes,
                             w.data_offset, w.data_bytes, rec['present_blocks'], rec['dropped_blocks'],
                             rec['zero_chunks'], rec['raw_chunks'], rec['lzfse_chunks'], bytes.fromhex(rec['table_sha256']))
        header[4064:] = hashlib.sha256(header[:4064]).digest()
        f.seek(0)
        f.write(header)
    return records, store_bytes


# ---------------------------------------------------------------------------------------------------------------- reader

class Store:
    """Reference reader: what the kernel driver (step 5) does, in Python. Every check the kernel needs is here."""

    def __init__(self, path, anchors, codec=None):
        """anchors: {window name: trusted key anchor (395 bytes)}; the kernel compiles its anchor in."""
        self.f = open(path, 'rb')
        try:
            self._open(anchors, codec)
        except BaseException:
            self.f.close()
            raise

    def _open(self, anchors, codec):
        self.size = os.fstat(self.f.fileno()).st_size
        self.codec = codec
        h = self.read(0, HEADER_BYTES)
        magic, version, hbytes, count, chunk, store_bytes, flags = HEAD.unpack_from(h)
        if (magic, version, hbytes, chunk, flags) != (MAGIC, VERSION, HEADER_BYTES, CHUNK, 0):
            raise ValueError('not an OPROOT01 version 1 store with 64 KiB chunks')
        if hashlib.sha256(h[:4064]).digest() != h[4064:]:
            raise ValueError('store header checksum')
        if store_bytes != self.size or not 1 <= count <= MAX_WINDOWS:
            raise ValueError('store size or window count')
        self.windows = {}
        for i in range(count):
            v = WINDOW.unpack_from(h, 64 + WINDOW.size * i)
            name = v[0].rstrip(b'\0').decode()
            w = dict(zip(('image_bytes', 'block_count', 'chunk_count', 'manifest_offset', 'manifest_bytes', 'table_offset',
                          'table_bytes', 'data_offset', 'data_bytes', 'present_blocks', 'dropped_blocks', 'zero_chunks',
                          'raw_chunks', 'lzfse_chunks'), v[2:16]))
            w['table_sha256'] = v[16]
            for off, n in (('manifest_offset', 'manifest_bytes'), ('table_offset', 'table_bytes'),
                           ('data_offset', 'data_bytes')):
                if w[off] % 4096 or w[off] < HEADER_BYTES or w[off] + w[n] > self.size:
                    raise ValueError(f'{name}: section {off} outside the store')
            if (w['chunk_count'] != (w['image_bytes'] + CHUNK - 1) // CHUNK or
                    w['table_bytes'] != w['chunk_count'] * ENTRY.size or
                    w['manifest_bytes'] != VR_HEADER + VR_SIGNATURE + w['block_count'] * 32):
                raise ValueError(f'{name}: window sizes do not agree')
            envelope = self.read(w['manifest_offset'], w['manifest_bytes'])
            if name not in anchors:
                raise ValueError(f'{name}: no trusted key for this window')
            m = Manifest(envelope[:VR_HEADER + VR_SIGNATURE], anchors[name])   # vr_open: key, signature ...
            hashes = envelope[VR_HEADER + VR_SIGNATURE:]
            if hashlib.sha256(hashes).digest() != m.table_sha256:             # ... and the hash table
                raise ValueError(f'{name}: block hash table does not match the signed manifest')
            if (m.image_bytes, m.block_count) != (w['image_bytes'], w['block_count']):
                raise ValueError(f'{name}: window sizes differ from the signed manifest')
            w['manifest'], w['hashes'] = m, hashes
            w['table'] = self.read(w['table_offset'], w['table_bytes'])
            self.windows[name] = w

    def close(self):
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def read(self, offset, n):
        self.f.seek(offset)
        data = self.f.read(n)
        if len(data) != n:
            raise ValueError('read past the end of the store')
        return data

    def chunk(self, name, index):
        """(present mask, decoded bytes of the chunk)."""
        w = self.windows[name]
        if index >= w['chunk_count']:
            raise IndexError(index)
        off, stored, present, kind = ENTRY.unpack_from(w['table'], index * ENTRY.size)
        length = min(CHUNK, w['image_bytes'] - index * CHUNK)
        if off + stored > w['data_bytes']:
            raise OSError(errno.EIO, f'{name} chunk {index}: outside the data section')
        if kind == KIND_ZERO:
            body = bytes(length) if stored == 0 else None
        elif kind == KIND_RAW:
            body = self.read(w['data_offset'] + off, stored) if stored == length else None
        elif kind == KIND_LZFSE:
            try:                                  # a damaged stream is a failed read, never more
                body = self.codec.decode(self.read(w['data_offset'] + off, stored), length)
            except Exception:
                body = None
        else:
            body = None
        if body is None or len(body) != length:
            raise OSError(errno.EIO, f'{name} chunk {index}: kind {kind}, {stored} bytes do not give {length} bytes')
        return present, body

    def read_block(self, name, block):
        """The 4 KiB block (shorter at the image end), verified; OSError(EIO) for a dropped or damaged block."""
        w = self.windows[name]
        if block >= w['block_count']:
            raise IndexError(block)
        present, body = self.chunk(name, block // PER)
        i = block % PER
        if not present >> i & 1:
            raise OSError(errno.EIO, f'{name} block {block}: dropped')
        data = body[i * BLOCK:(i + 1) * BLOCK]
        if hashlib.sha256(data).digest() != w['hashes'][block * 32:block * 32 + 32]:     # vr_verify_block
            raise OSError(errno.EIO, f'{name} block {block}: does not match the manifest')
        return data


def _verify_init(path, anchors):
    _job['store'] = Store(path, anchors, Lzfse())


def _verify_span(args):
    name, first, last = args
    s = _job['store']
    w = s.windows[name]
    zero = bytes(BLOCK)
    counts = dict(present=0, chunks=0)
    for c in range(first, last):
        present, body = s.chunk(name, c)
        counts['chunks'] += 1
        for i in range(0, len(body), BLOCK):
            b = c * PER + i // BLOCK
            data = body[i:i + BLOCK]
            if present >> (i // BLOCK) & 1:
                if hashlib.sha256(data).digest() != w['hashes'][b * 32:b * 32 + 32]:
                    raise OSError(errno.EIO, f'{name} block {b}: does not match the manifest')
                counts['present'] += 1
            elif data != zero[:len(data)]:
                raise ValueError(f'{name} block {b}: dropped but not zero')
        if present >> ((len(body) + BLOCK - 1) // BLOCK):
            raise ValueError(f'{name} chunk {c}: present bits past the image end')
    return name, counts


def verify(path, anchors, jobs=0, codec=None, log=print):
    """Decode every chunk and check every present block; returns per-window counts."""
    with Store(path, anchors, codec or (None if jobs and jobs > 1 else Lzfse())) as store:
        return _verify(store, path, jobs, log)


def _verify(store, path, jobs, log):
    out = {}
    for name, w in store.windows.items():
        if hashlib.sha256(w['table']).digest() != w['table_sha256']:
            raise ValueError(f'{name}: chunk table checksum')
        at, kinds = 0, [0, 0, 0]
        for c in range(w['chunk_count']):          # the builder packs the data back to back, in chunk order
            off, stored, present, kind = ENTRY.unpack_from(w['table'], c * ENTRY.size)
            if off != at or kind > KIND_LZFSE:
                raise ValueError(f'{name} chunk {c}: not packed in order')
            at += stored
            kinds[kind] += 1
        if at != w['data_bytes'] or kinds != [w['zero_chunks'], w['raw_chunks'], w['lzfse_chunks']]:
            raise ValueError(f'{name}: chunk table does not add up to the header')
        out[name] = dict(present=0, chunks=0)
    tasks = [(name, c, min(c + 4096, w['chunk_count'])) for name, w in store.windows.items()
             for c in range(0, w['chunk_count'], 4096)]
    if jobs and jobs > 1:
        with multiprocessing.get_context('spawn').Pool(jobs, _verify_init, (str(path), {n: w['manifest'].anchor for n, w in
                                                                                        store.windows.items()})) as pool:
            results = list(pool.imap_unordered(_verify_span, tasks))
    else:
        _job['store'] = store
        results = [_verify_span(t) for t in tasks]
    for name, counts in results:
        for k in counts:
            out[name][k] += counts[k]
    for name, w in store.windows.items():
        if out[name]['present'] != w['present_blocks'] or out[name]['chunks'] != w['chunk_count']:
            raise ValueError(f'{name}: {out[name]["present"]} present blocks, the header says {w["present_blocks"]}')
        log(f'{name}: {w["chunk_count"]} chunks decoded, {out[name]["present"]} blocks match the signed manifest, '
            f'{w["dropped_blocks"]} dropped')
    return out


# ------------------------------------------------------------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    b = sub.add_parser('build')
    b.add_argument('--policy', required=True, type=Path, help='dir with <window>/manifest.header.bin and trusted-key.bin')
    b.add_argument('--out', required=True, type=Path)
    b.add_argument('--drop', action='append', help='a trim group to drop (repeat); default: the store default')
    b.add_argument('--group', action='append', default=[], help='NAME=GLOB: add a glob to a group or a new group')
    b.add_argument('--budget', type=int, default=DEFAULT_BUDGET, help='largest store in bytes (0: no limit)')
    b.add_argument('--jobs', type=int, default=os.cpu_count() or 2)
    b.add_argument('images', nargs='+', help='NAME=PATH (NAME: OS, SystemOS)')
    v = sub.add_parser('verify')
    v.add_argument('--policy', required=True, type=Path)
    v.add_argument('--jobs', type=int, default=os.cpu_count() or 2)
    v.add_argument('store', type=Path)
    a = ap.parse_args()

    if a.cmd == 'verify':
        anchors = {d.name: (d / 'trusted-key.bin').read_bytes() for d in a.policy.iterdir() if (d / 'trusted-key.bin').exists()}
        verify(a.store, anchors, a.jobs)
        print('VERIFIED')
        return 0

    a.out.mkdir(parents=True, exist_ok=True)
    groups = store_groups(a.group)
    drop = a.drop or default_drop(groups)
    unknown = set(drop) - {g['name'] for g in groups}
    if unknown:
        ap.error(f'unknown trim groups: {", ".join(sorted(unknown))}')
    codec = Lzfse()
    report = [f'OPROOT01 store: chunks {CHUNK // 1024} KiB, {codec.name}; dropped groups: {", ".join(drop)}']
    for g in groups:
        report.append(f'  group {g["name"]:<20} {"DROP" if g["name"] in drop else "keep":<5} {g["note"]}')
    windows, paths_all = [], []
    for item in a.images:
        name, _, path = item.partition('=')
        m = Manifest.load(a.policy, name)
        t0 = time.time()
        mask, paths, files, lines = dropped_blocks(path, groups, drop)
        report.append(f'=== {name}: {Path(path).name}, {m.image_bytes} bytes, volume {m.volume_uuid.hex()}')
        report.extend(lines)
        report.append(f'  dropped: {len(paths)} paths, {BM.ones(mask)} blocks ({BM.ones(mask) * BLOCK / BM.GIB:.3f} GiB); '
                      f'files per group: ' + ', '.join(f'{n} {files[n]}' for n in drop) + f'; {time.time() - t0:.0f} s')
        paths_all.extend(f'{name}:{p}' for p in paths)
        windows.append(Window(name, path, m, mask))
    store = a.out / 'store.bin'
    records, size = build(windows, store, a.jobs)
    over = None
    if a.budget and size > a.budget:
        over = f'store is {size} bytes, more than the budget {a.budget} ({(size - a.budget) / BM.MIB:.1f} MiB over)'
    info = dict(format='OPROOT01', version=VERSION, chunk_bytes=CHUNK, store_bytes=size, budget=a.budget,
                dropped_groups=drop, windows=records, fits=over is None)
    if over is None:
        h = hashlib.sha256()
        with open(store, 'rb') as f:
            for data in iter(lambda: f.read(64 * BM.MIB), b''):
                h.update(data)
        info['sha256'] = h.hexdigest()
    if not a.budget:
        verdict = 'no budget'
    elif over is None:
        verdict = f'budget {a.budget} = {a.budget / BM.GIB:.3f} GiB, margin {(a.budget - size) / BM.MIB:.1f} MiB'
    else:
        verdict = over
    report.append(f'store: {size} bytes = {size / BM.GIB:.3f} GiB; {verdict}')
    (a.out / 'store.json').write_text(json.dumps(info, indent=2) + '\n')
    (a.out / 'report.txt').write_text('\n'.join(report + ['dropped paths:'] + paths_all) + '\n')
    rows = ['| window | image GiB | dropped GiB | stored GiB (data) | zero / raw / LZFSE chunks |', '| --- | --- | --- | --- | --- |']
    for r in records:
        rows.append(f'| {r["name"]} | {r["image_bytes"] / BM.GIB:.3f} | {r["dropped_blocks"] * BLOCK / BM.GIB:.3f} | '
                    f'{r["data_bytes"] / BM.GIB:.3f} | {r["zero_chunks"]} / {r["raw_chunks"]} / {r["lzfse_chunks"]} |')
    rows.append(f'\nStore {size / BM.GIB:.3f} GiB ({size} bytes); budget {a.budget / BM.GIB:.3f} GiB: '
                + ('fits' if over is None else 'DOES NOT FIT') + f'. Dropped groups: {", ".join(drop)}.')
    (a.out / 'summary.md').write_text('\n'.join(rows) + '\n')
    print('\n'.join(report[:40]))
    print('\n'.join(rows))
    if over is not None:
        store.unlink(missing_ok=True)
        print(f'::error::{over}')
        return 3
    return 0


if __name__ == '__main__':
    sys.exit(main())
