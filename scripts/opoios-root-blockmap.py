#!/usr/bin/env python3
"""OPOIOS: block map and chunk compression of the iOS root images for a trimmed, compressed RAM root (stage 4, path 1).

    python3 scripts/opoios-root-blockmap.py --out DIR [--jobs N] [--group NAME=GLOB ...] NAME=IMAGE [NAME=IMAGE ...]

The RAM root keeps the original OS and SystemOS disk images byte for byte, minus the blocks that only dropped files use (a read
of one fails), and stores the rest as compressed chunks. This measures what that store would hold:

1. Block map. The APFS container of each image is read (every volume: the file-system tree, a sealed volume's fext tree, and the
   data streams of extended attributes, where APFS-compressed files keep their data) and every 4 KiB block that holds file data
   is attributed to the files that use it. Blocks that no file uses (metadata, the integrity tree, free space) are always kept.
2. Trim groups. Each group is a set of path globs. A file is dropped only when every path that names it matches; a block is
   dropped only when no kept file uses it. The report gives each group alone and the variants below.
3. Chunk compression. Every chunk of 16, 64 and 128 KiB is compressed with each algorithm (macOS libcompression: LZ4 raw and
   LZFSE; elsewhere zlib, for host tests), for the variants full (all nonzero blocks), default (the default groups dropped) and
   aggressive (all groups dropped). A chunk without a kept nonzero block is not stored; dropped blocks inside a kept chunk are
   compressed as zeros. A chunk that does not get smaller is stored as it is.

Writes DIR/report.txt (sizes and path names only, nothing from the files) and DIR/summary.md (totals). Read-only: the images are
opened for reading and nothing is written next to them.

APFS reading adapted from UniXNU-aston scripts/apfs-read.py (BSD-2-Clause-Patent), extended by the extended-attribute streams.
"""
import argparse
import ctypes
import ctypes.util
import fnmatch
import multiprocessing
import os
import re
import struct
import sys
import time
import zlib
from pathlib import Path

GIB = 1 << 30
MIB = 1 << 20
BLOCK = 4096
CHUNKS = (16384, 65536, 131072)
SPAN = 256 * MIB                     # one worker task
RAM_ROOT_REGION = 0xBFFDBF000 - 0xA00000000   # the phone's free range above the XNU window (docs/07-stage4-ram-root.md)

# name, in the default trim, include globs, exclude regex (matched against the path), what it is
GROUPS = [
    ('ane', True, ['*/H1[0-9].bundle/*', '*/H1[0-9][A-Z].bundle/*', '*.hwx', '*/ane_compile/*', '*_ane/*'], None,
     'Neural Engine programs; SM8550 has no Neural Engine'),
    ('staged-apps', True, ['/private/var/staged_system_apps/*'], None,
     'apps installed on first boot (Maps and others)'),
    ('linguistic', True, ['/System/Library/LinguisticData/*'], r'(^|[/_.-])(en|ru|root)([/_.-]|$)',
     'language data except English and Russian'),
    ('preinstalled-assets', True, ['/System/Library/PreinstalledAssetsV2/*'], None, 'preinstalled MobileAsset content'),
    ('update', True, ['/usr/standalone/update/*'], None, 'update ramdisk and baseband firmware'),
    ('tts-voices', True, ['/System/Library/PrivateFrameworks/VoiceServices.framework/TTSResources/*'], None,
     'text-to-speech voices'),
    ('dyld-symbols', True, ['/System/Library/Caches/com.apple.dyld/*.symbols'], None,
     'local symbols of the dyld shared cache'),
    ('ml-models', False, ['*.mlmodelc/*', '*.espresso.*', '*.bnnsir', '*.mlpackage/*', '*.mil'], None,
     'machine-learning models that can also run on the CPU'),
    ('vision-resources', False, [f'/System/Library/PrivateFrameworks/{n}.framework/*' for n in (
        'MediaAnalysis', 'VisualLookUp', 'CoreSceneUnderstanding', 'EmbeddingCore', 'VisionCore', 'VisualIntelligenceCore',
        'GESS', 'AppleCV3D')], None,
     'resources of photo and vision analysis frameworks (their code is in the dyld shared cache)'),
]
VARIANTS = ('full', 'default', 'aggressive')

# ---------------------------------------------------------------------------------------------------------------- APFS

OBJ = struct.Struct('<QQQII')
J_INODE, J_XATTR, J_EXTENT, J_DREC = 3, 4, 8, 9
ROOT_DIR = 2


def fletcher64(block):
    words = struct.unpack_from(f'<{len(block) // 4}I', block)
    s1 = s2 = 0
    for w in words[2:]:
        s1 = (s1 + w) % 0xFFFFFFFF
        s2 = (s2 + s1) % 0xFFFFFFFF
    c1 = 0xFFFFFFFF - (s1 + s2) % 0xFFFFFFFF
    c2 = 0xFFFFFFFF - (s1 + c1) % 0xFFFFFFFF
    return c2 << 32 | c1


class Container:
    def __init__(self, path):
        self.f = open(path, 'rb')
        self.bs = 4096
        head = self.block(0)
        if head[32:36] != b'NXSB':
            raise ValueError('no APFS container superblock at block 0')
        self.bs = struct.unpack_from('<I', head, 36)[0]
        if self.bs != BLOCK:
            raise ValueError(f'APFS block size {self.bs}, expected {BLOCK}')
        base, blocks = struct.unpack_from('<Q', head, 112)[0], struct.unpack_from('<I', head, 104)[0] & 0x7FFFFFFF
        best = None
        for b in range(base, base + blocks):
            blk = self.block(b)
            cksum, _oid, xid, otype, _ = OBJ.unpack_from(blk)
            if blk[32:36] == b'NXSB' and otype & 0xFFFF == 1 and cksum == fletcher64(blk) and (best is None or xid > best[0]):
                best = (xid, blk)
        if best is None:
            raise ValueError('no valid container superblock in the checkpoint area')
        self.xid, self.nx = best
        self.block_count = struct.unpack_from('<Q', self.nx, 40)[0]
        self.omap = self.omap_root(struct.unpack_from('<Q', self.nx, 160)[0])
        self.fs_oids = [o for o in struct.unpack_from('<100Q', self.nx, 184) if o]

    def block(self, n):
        self.f.seek(n * self.bs)
        return self.f.read(self.bs)

    def omap_root(self, omap_paddr):
        return struct.unpack_from('<Q', self.block(omap_paddr), 48)[0]

    def node(self, paddr):
        blk = self.block(paddr)
        flags, level, nkeys = struct.unpack_from('<HHI', blk, 32)
        toff, tlen = struct.unpack_from('<HH', blk, 40)
        keys_at = 56 + toff + tlen
        vals_end = self.bs - (40 if flags & 1 else 0)
        entries = []
        for i in range(nkeys):
            if flags & 4:
                koff, voff = struct.unpack_from('<HH', blk, 56 + toff + 4 * i)
                klen, vlen = 16, (16 if flags & 2 else 8)
            else:
                koff, klen, voff, vlen = struct.unpack_from('<HHHH', blk, 56 + toff + 8 * i)
            key = blk[keys_at + koff:keys_at + koff + klen]
            val = blk[vals_end - voff:vals_end - voff + vlen] if voff != 0xFFFF else b''
            entries.append((key, val))
        return flags, level, entries

    def omap_lookup(self, root, oid, xid):
        paddr = root
        while True:
            _flags, level, entries = self.node(paddr)
            pick = None
            for key, val in entries:
                k_oid, k_xid = struct.unpack_from('<QQ', key)
                if (k_oid, k_xid) <= (oid, xid):
                    pick = (k_oid, k_xid, val)
                else:
                    break
            if pick is None:
                return None
            if level == 0:
                return struct.unpack_from('<IIQ', pick[2])[2] if pick[0] == oid else None
            paddr = struct.unpack_from('<Q', pick[2])[0]

    def walk(self, root, resolve, base=0):
        stack = [(root, None)]
        while stack:
            paddr, expect = stack.pop()
            _flags, level, entries = self.node(paddr)
            if expect is not None and level != expect:
                raise ValueError(f'B-tree node at block {paddr} has level {level}, its parent expects {expect}')
            if level == 0:
                yield from entries
            else:
                stack.extend((resolve(struct.unpack_from('<Q', val)[0] + base), level - 1) for _, val in reversed(entries))


class Volume:
    def __init__(self, nx, index):
        self.nx = nx
        oid = nx.fs_oids[index]
        paddr = nx.omap_lookup(nx.omap, oid, nx.xid)
        self.sb = nx.block(paddr)
        if self.sb[32:36] != b'APSB':
            raise ValueError(f'volume {index}: no APSB at block {paddr}')
        self.name = self.sb[704:960].split(b'\0')[0].decode(errors='replace')
        self.flags = struct.unpack_from('<Q', self.sb, 264)[0]
        self.hashed = struct.unpack_from('<Q', self.sb, 56)[0] & 0x9 != 0
        self.role = struct.unpack_from('<H', self.sb, 964)[0]
        self.vomap = nx.omap_root(struct.unpack_from('<Q', self.sb, 128)[0])
        self.root_tree = struct.unpack_from('<Q', self.sb, 136)[0]
        self.fext_tree = struct.unpack_from('<Q', self.sb, 1032)[0]
        self.sealed = bool(struct.unpack_from('<I', self.sb, 116)[0] & 0x40000000)

    def resolve(self, oid):
        if self.sealed:
            return oid
        paddr = self.nx.omap_lookup(self.vomap, oid, self.nx.xid)
        if paddr is None:
            raise ValueError(f'object {oid:#x} not in the volume object map')
        return paddr

    def level_at(self, oid):
        try:
            paddr = self.resolve(oid)
        except ValueError:
            return None
        return struct.unpack_from('<H', self.nx.block(paddr), 34)[0]

    def load(self):
        """children: dir oid -> {name: oid}; private: inode oid -> private id; streams: inode oid -> [stream ids];
        extents: stream id -> [(physical block, block count)]; compressed: inode oids with a decmpfs attribute."""
        if self.flags & 1 == 0:
            raise ValueError(f'volume "{self.name}" is encrypted')
        self.children, self.private, self.streams, self.extents, self.compressed, self.modes = {}, {}, {}, {}, set(), {}
        root = self.resolve(self.root_tree)
        base = 0
        flags, level, entries = self.nx.node(root)
        if flags & 8 and level and entries:   # hashed tree of a sealed volume: child ids relative to the root's
            first = struct.unpack_from('<Q', entries[0][1])[0]
            fits = [b for b in (0, self.root_tree) if self.level_at(first + b) == level - 1]
            if not fits:
                raise ValueError('sealed file-system tree: no child id base gives its root a child one level down')
            base = fits[0]
        for key, val in self.nx.walk(root, self.resolve, base):
            hdr = struct.unpack_from('<Q', key)[0]
            oid, kind = hdr & 0x0FFFFFFFFFFFFFFF, hdr >> 60
            if kind == J_DREC:
                if self.hashed:
                    n = struct.unpack_from('<I', key, 8)[0] & 0x3FF
                    name = key[12:12 + n].rstrip(b'\0').decode(errors='replace')
                else:
                    n = struct.unpack_from('<H', key, 8)[0]
                    name = key[10:10 + n].rstrip(b'\0').decode(errors='replace')
                self.children.setdefault(oid, {})[name] = struct.unpack_from('<Q', val)[0]
            elif kind == J_INODE:
                self.private[oid] = struct.unpack_from('<Q', val, 8)[0]
                self.modes[oid] = struct.unpack_from('<H', val, 80)[0]
            elif kind == J_EXTENT:
                logical, = struct.unpack_from('<Q', key, 8)
                length, phys = struct.unpack_from('<QQ', val)
                self.add_extent(oid, length & 0x00FFFFFFFFFFFFFF, phys)
            elif kind == J_XATTR:
                n, = struct.unpack_from('<H', key, 8)
                name = key[10:10 + n].rstrip(b'\0').decode(errors='replace')
                xflags, = struct.unpack_from('<H', val)
                if name == 'com.apple.decmpfs':
                    self.compressed.add(oid)
                if xflags & 1 and len(val) >= 12:   # XATTR_DATA_STREAM: j_xattr_dstream_t {xattr_obj_id, dstream}
                    self.streams.setdefault(oid, []).append(struct.unpack_from('<Q', val, 4)[0])
        if self.fext_tree:
            for key, val in self.nx.walk(self.fext_tree, lambda block: block):
                private, _logical = struct.unpack_from('<QQ', key)
                length, phys = struct.unpack_from('<QQ', val)
                self.add_extent(private, length & 0x00FFFFFFFFFFFFFF, phys)

    def add_extent(self, stream, length, phys):
        if phys and length:
            self.extents.setdefault(stream, []).append((phys, (length + BLOCK - 1) // BLOCK))

    def files(self):
        """(path, inode oid) of every non-directory, every hard link separately."""
        stack = [(ROOT_DIR, '')]
        while stack:
            oid, prefix = stack.pop()
            for name, child in self.children.get(oid, {}).items():
                path = f'{prefix}/{name}'
                if child in self.children or self.modes.get(child, 0) & 0o170000 == 0o040000:
                    stack.append((child, path))
                else:
                    yield path, child

    def inode_extents(self, oid):
        for stream in [self.private.get(oid, oid)] + self.streams.get(oid, []):
            yield from self.extents.get(stream, ())


# ------------------------------------------------------------------------------------------------------- trim groups

def group_matchers(extra):
    groups = [dict(name=n, default=d, globs=list(g), exclude=re.compile(x) if x else None, note=t) for n, d, g, x, t in GROUPS]
    for item in extra:
        name, _, glob = item.partition('=')
        found = [g for g in groups if g['name'] == name]
        if found:
            found[0]['globs'].append(glob)
        else:
            groups.append(dict(name=name, default=False, globs=[glob], exclude=None, note='from the command line'))
    for g in groups:     # one regular expression per group; fnmatch's * also crosses '/'
        g['match'] = re.compile('|'.join(f'(?:{fnmatch.translate(glob)})' for glob in g['globs']))
    return groups


def in_group(group, path):
    return group['match'].match(path) is not None and not (group['exclude'] and group['exclude'].search(path))


def mark(bitmap, extents, total):
    """Set the blocks of extents in a 0/1 bytearray; returns the blocks outside the image."""
    outside = 0
    for phys, count in extents:
        end = min(phys + count, total)
        if end > phys:
            bitmap[phys:end] = b'\1' * (end - phys)
        outside += phys + count - end
    return outside


def ones(data):
    return data.count(1)


def andnot(a, b):
    """0/1 bytes: a and not b, through big integers."""
    x = int.from_bytes(a, 'little') & ~int.from_bytes(b, 'little')
    return x.to_bytes(len(a), 'little')


def orb(a, b):
    return (int.from_bytes(a, 'little') | int.from_bytes(b, 'little')).to_bytes(len(a), 'little')


def blockmap(name, image, groups, report):
    """Per image: the file-data mask and the dropped-block masks of every variant and group."""
    size = image.stat().st_size
    total = (size + BLOCK - 1) // BLOCK
    nx = Container(image)
    report.append(f'  container: block size {nx.bs}, {nx.block_count} blocks, xid {nx.xid}, {len(nx.fs_oids)} volume(s)')
    used = bytearray(total)                 # any file
    kept = {v: bytearray(total) for v in VARIANTS[1:]}
    alone = {g['name']: bytearray(total) for g in groups}
    alone_kept = {g['name']: bytearray(total) for g in groups}
    paths_by_inode = {}
    stats = dict(files=0, links=0, compressed=0, streams=0, outside=0)
    dir_blocks, ext_blocks, group_files = {}, {}, {g['name']: 0 for g in groups}
    for index in range(len(nx.fs_oids)):
        volume = Volume(nx, index)
        volume.load()
        report.append(f'  volume [{index}] "{volume.name}" role {volume.role:#x} sealed {volume.sealed}: '
                      f'{len(volume.private)} inodes, {sum(len(e) for e in volume.extents.values())} extents, '
                      f'{len(volume.compressed)} compressed, {sum(len(s) for s in volume.streams.values())} attribute streams')
        for path, oid in volume.files():
            paths_by_inode.setdefault((index, oid), []).append(path)
        for (vindex, oid), paths in paths_by_inode.items():
            if vindex != index:
                continue
            extents = list(volume.inode_extents(oid))
            stats['files'] += 1
            stats['links'] += len(paths) - 1
            stats['compressed'] += oid in volume.compressed
            stats['streams'] += len(volume.streams.get(oid, ()))
            stats['outside'] += mark(used, extents, total)
            blocks = sum(c for _, c in extents)
            member = {g['name'] for g in groups if all(in_group(g, p) for p in paths)}
            for g in groups:
                mark(alone[g['name']] if g['name'] in member else alone_kept[g['name']], extents, total)
                group_files[g['name']] += g['name'] in member
            dropped = {'default': any(g['default'] and g['name'] in member for g in groups), 'aggressive': bool(member)}
            for v in VARIANTS[1:]:
                if not dropped[v]:
                    mark(kept[v], extents, total)
            path = paths[0]
            parts = path.split('/')
            for depth in range(2, min(len(parts), 7)):
                prefix = '/'.join(parts[:depth])
                dir_blocks[prefix] = dir_blocks.get(prefix, 0) + blocks
            leaf = parts[-1].lower()
            ext = leaf.rsplit('.', 1)[1] if '.' in leaf[1:] else '(none)'
            ext_blocks[ext] = ext_blocks.get(ext, 0) + blocks
    used = bytes(used)
    dropped = {v: andnot(used, bytes(kept[v])) for v in VARIANTS[1:]}
    dropped['full'] = bytes(total)
    report.append(f'  files: {stats["files"]} inodes ({stats["links"]} extra hard links), {stats["compressed"]} APFS-compressed, '
                  f'{stats["streams"]} attribute data streams; blocks used by files {ones(used)} = '
                  f'{ones(used) * BLOCK / GIB:.3f} GiB; extent blocks outside the image {stats["outside"]}')
    report.append('  trim groups alone (dropped = used by the group\'s files and by no other file):')
    for g in groups:
        alone_dropped = ones(andnot(bytes(alone[g['name']]), bytes(alone_kept[g['name']])))
        report.append(f'    {g["name"]:<20} {"default" if g["default"] else "extra":<8} {group_files[g["name"]]:>7} files '
                      f'{alone_dropped * BLOCK / GIB:8.3f} GiB  {g["note"]}')
    for v in VARIANTS[1:]:
        report.append(f'  variant {v}: dropped {ones(dropped[v]) * BLOCK / GIB:.3f} GiB')
    report.append('  directories by file blocks (depth up to 5, at least 64 MiB, hard links counted once):')
    for prefix, blocks in sorted(dir_blocks.items(), key=lambda r: -r[1])[:80]:
        if blocks * BLOCK >= 64 * MIB:
            report.append(f'    {blocks * BLOCK / MIB:10.1f} MiB  {prefix}')
    report.append('  file name extensions by file blocks (top 30):')
    for ext, blocks in sorted(ext_blocks.items(), key=lambda r: -r[1])[:30]:
        report.append(f'    {blocks * BLOCK / MIB:10.1f} MiB  .{ext}')
    return used, dropped, total


# -------------------------------------------------------------------------------------------------------- compression

ALGORITHMS = {}           # name -> (encode(data) -> size or 0, decode(blob, n) -> bytes)
_lib = None


def setup_algorithms():
    global _lib
    ALGORITHMS.clear()
    if sys.platform == 'darwin':
        _lib = ctypes.CDLL(ctypes.util.find_library('compression') or '/usr/lib/libcompression.dylib')
        _lib.compression_encode_buffer.restype = ctypes.c_size_t
        _lib.compression_encode_buffer.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
                                                   ctypes.c_void_p, ctypes.c_int]
        _lib.compression_decode_buffer.restype = ctypes.c_size_t
        _lib.compression_decode_buffer.argtypes = _lib.compression_encode_buffer.argtypes
        _lib.compression_encode_scratch_buffer_size.restype = ctypes.c_size_t
        _lib.compression_decode_scratch_buffer_size.restype = ctypes.c_size_t
        _lib.compression_encode_scratch_buffer_size.argtypes = [ctypes.c_int]
        _lib.compression_decode_scratch_buffer_size.argtypes = [ctypes.c_int]
        for name, code in (('lz4', 0x101), ('lzfse', 0x801)):     # COMPRESSION_LZ4_RAW, COMPRESSION_LZFSE
            enc_scratch = ctypes.create_string_buffer(_lib.compression_encode_scratch_buffer_size(code) or 1)
            dec_scratch = ctypes.create_string_buffer(_lib.compression_decode_scratch_buffer_size(code) or 1)
            out = ctypes.create_string_buffer(max(CHUNKS) * 2)

            def encode(data, code=code, out=out, scratch=enc_scratch):
                n = _lib.compression_encode_buffer(out, len(data), data, len(data), scratch, code)
                return ctypes.string_at(out, n) if n else b''

            def decode(blob, n, code=code, scratch=dec_scratch):
                dst = ctypes.create_string_buffer(n)
                got = _lib.compression_decode_buffer(dst, n, blob, len(blob), scratch, code)
                return ctypes.string_at(dst, got)
            ALGORITHMS[name] = (encode, decode)
    else:
        def encode(data):
            c = zlib.compressobj(5, zlib.DEFLATED, -15)
            blob = c.compress(data) + c.flush()
            return blob if len(blob) < len(data) else b''
        ALGORITHMS['zlib'] = (encode, lambda blob, n: zlib.decompress(blob, -15, n))


_job = {}


def worker_init(path, masks):
    setup_algorithms()
    _job['path'] = path
    _job['masks'] = masks      # variant -> 0/1 bytes per block, 1 = dropped


def worker_span(start):
    """Sums over one span: {(variant, chunk, algorithm): [stored bytes, stored chunks, raw chunks]},
    {variant: kept nonzero blocks}, nonzero blocks."""
    zero = bytes(BLOCK)
    sums, kept_blocks = {}, {v: 0 for v in VARIANTS}
    nonzero_total = 0
    masks = _job['masks']
    big = max(CHUNKS)
    with open(_job['path'], 'rb') as f:
        f.seek(start)
        data = f.read(SPAN)
    for at in range(0, len(data), big):
        piece = data[at:at + big]
        if len(piece) % BLOCK:
            piece += bytes(BLOCK - len(piece) % BLOCK)
        first = (start + at) // BLOCK
        nonzero = [piece[i:i + BLOCK] != zero for i in range(0, len(piece), BLOCK)]
        nonzero_total += sum(nonzero)
        kept = {}
        for v in VARIANTS:
            mask = masks[v]
            kept[v] = tuple(nz and not (first + i < len(mask) and mask[first + i]) for i, nz in enumerate(nonzero))
            kept_blocks[v] += sum(kept[v])
        for chunk in CHUNKS:
            per = chunk // BLOCK
            for c in range(0, len(nonzero), per):
                done = {}          # the same kept blocks in several variants: compress once
                for v in VARIANTS:
                    sel = kept[v][c:c + per]
                    if not any(sel):
                        continue
                    if sel not in done:
                        body = piece[c * BLOCK:(c + len(sel)) * BLOCK]
                        if any(nz and not k for nz, k in zip(nonzero[c:c + per], sel)):
                            body = b''.join(body[i * BLOCK:(i + 1) * BLOCK] if k else zero for i, k in enumerate(sel))
                        sizes = {}
                        for name, (encode, _) in ALGORITHMS.items():
                            blob = encode(body)
                            sizes[name] = (len(blob), False) if blob and len(blob) < len(body) else (len(body), True)
                        done[sel] = sizes
                    for name, (stored, raw) in done[sel].items():
                        row = sums.setdefault((v, chunk, name), [0, 0, 0])
                        row[0] += stored
                        row[1] += 1
                        row[2] += raw
    return sums, kept_blocks, nonzero_total


def compress_image(image, masks, jobs):
    size = image.stat().st_size
    starts = list(range(0, size, SPAN))
    sums, kept, nonzero = {}, {v: 0 for v in VARIANTS}, 0
    with multiprocessing.get_context('spawn').Pool(jobs, worker_init, (str(image), masks)) as pool:
        for part_sums, part_kept, part_nonzero in pool.imap_unordered(worker_span, starts):
            for key, row in part_sums.items():
                total = sums.setdefault(key, [0, 0, 0])
                for i in range(3):
                    total[i] += row[i]
            for v in VARIANTS:
                kept[v] += part_kept[v]
            nonzero += part_nonzero
    return sums, kept, nonzero


def decode_speed(image, used, report):
    """Single-thread decode speed of each algorithm on the first 256 MiB of 64 KiB chunks that hold file data."""
    setup_algorithms()
    chunk, wanted = 65536, 4096
    pieces = []
    with open(image, 'rb') as f:
        per = chunk // BLOCK
        for c in range(0, len(used), per):
            if any(used[c:c + per]):
                f.seek(c * BLOCK)
                body = f.read(chunk)
                if len(body) == chunk:
                    pieces.append(body)
                if len(pieces) == wanted:
                    break
    if not pieces:
        return
    for name, (encode, decode) in ALGORITHMS.items():
        blobs = [encode(p) for p in pieces]
        t0 = time.perf_counter()
        for p, b in zip(pieces, blobs):
            out = decode(b, chunk) if b else p
            if out != p:
                report.append(f'  decode check FAILED for {name}')
                break
        dt = time.perf_counter() - t0
        report.append(f'  decode {name:<6} {len(pieces) * chunk / MIB / dt:8.0f} MiB/s single thread '
                      f'({len(pieces)} chunks of 64 KiB, ratio {len(pieces) * chunk / max(sum(len(b) or chunk for b in blobs), 1):.2f})')


# ---------------------------------------------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--jobs', type=int, default=os.cpu_count() or 2)
    ap.add_argument('--group', action='append', default=[], help='NAME=GLOB: add a glob to a group or a new extra group')
    ap.add_argument('images', nargs='+', help='NAME=PATH of a raw APFS container image')
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    setup_algorithms()
    groups = group_matchers(args.group)
    report = [f'algorithms: {", ".join(ALGORITHMS)}; chunks {", ".join(str(c // 1024) + " KiB" for c in CHUNKS)}; '
              f'RAM root region {RAM_ROOT_REGION / GIB:.3f} GiB']
    budget = {}
    for item in args.images:
        name, _, path = item.partition('=')
        image = Path(path)
        size = image.stat().st_size
        report.append(f'=== {name}: {image.name}, {size} bytes = {size / GIB:.3f} GiB')
        t0 = time.time()
        try:
            used, dropped, total = blockmap(name, image, groups, report)
        except (ValueError, struct.error, KeyError, IndexError) as error:
            report.append(f'  block map failed: {error!r}; compression measured for the full variant only')
            total = (size + BLOCK - 1) // BLOCK
            used, dropped = bytes(total), {v: bytes(total) for v in VARIANTS}
        report.append(f'  block map: {time.time() - t0:.0f} s')
        t0 = time.time()
        sums, kept, nonzero = compress_image(image, dropped, args.jobs)
        report.append(f'  compression: {time.time() - t0:.0f} s; nonzero blocks {nonzero} = {nonzero * BLOCK / GIB:.3f} GiB, '
                      f'of them not file data (metadata, integrity tree, free space) '
                      f'{max(nonzero - ones(used), 0) * BLOCK / GIB:.3f} GiB (approximate: file blocks may be zero)')
        report.append('  stored size (GiB) by variant, chunk and algorithm; kept nonzero blocks per variant:')
        for v in VARIANTS:
            report.append(f'    {v}: kept {kept[v] * BLOCK / GIB:.3f} GiB')
            for chunk in CHUNKS:
                cells = []
                for alg in ALGORITHMS:
                    stored, count, raw = sums.get((v, chunk, alg), [0, 0, 0])
                    cells.append(f'{alg} {stored / GIB:.3f} ({count} chunks, {raw} raw)')
                    budget[(name, v, chunk, alg)] = (stored, count, kept[v])
                report.append(f'      {chunk // 1024:>3} KiB: ' + '; '.join(cells))
        decode_speed(image, used, report)
        budget[(name, 'blocks')] = total
    summary = ['| variant | chunk | algorithm | ' + ' | '.join(n.partition('=')[0] for n in args.images) +
               ' | store with tables | fits 7.998 GiB |', '| --- ' * (5 + len(args.images)) + '|']
    for v in VARIANTS:
        for chunk in CHUNKS:
            for alg in ALGORITHMS:
                cells, store = [], 0
                for item in args.images:
                    name = item.partition('=')[0]
                    stored, count, _ = budget.get((name, v, chunk, alg), (0, 0, 0))
                    tables = budget.get((name, 'blocks'), 0) * 32 + count * 16   # VerifiedRoot hashes + chunk table
                    cells.append(f'{stored / GIB:.2f}')
                    store += stored + tables
                summary.append(f'| {v} | {chunk // 1024} KiB | {alg} | ' + ' | '.join(cells) +
                               f' | {store / GIB:.2f} GiB | {"yes" if store <= RAM_ROOT_REGION else "no"} |')
    (args.out / 'report.txt').write_text('\n'.join(report) + '\n')
    (args.out / 'summary.md').write_text('\n'.join(summary) + '\n')
    print('\n'.join(report))
    print('\n'.join(summary))


if __name__ == '__main__':
    sys.exit(main())
