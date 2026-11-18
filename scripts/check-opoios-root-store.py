#!/usr/bin/env python3
"""Host checks of the RAM root store reader (package/OpoiosRootStore.c) against stores written by opoios-root-store.py.

    python3 scripts/check-opoios-root-store.py --verified-root DIR [--store STORE.bin --key trusted-key.bin]

DIR is UniXNU's kits/VerifiedRoot (verified_root.c and its OpenSSL provider). Builds, with gcc and OpenSSL 3:
- ors-test: OpoiosRootStore.c, OpoiosLzfse.c, the vendored decoder (package/lzfse), verified_root.c and
  OpoiosRootStoreTests.c, with AddressSanitizer and UBSan (an -O2 build for the full store);
- liblzfse.so from package/lzfse, the LZFSE encoder of opoios-root-store.py here (OPOIOS_LZFSE_LIB).
Then on synthetic images signed with a throwaway RSA-3072 key, real LZFSE chunks: every block reads back equal to the
image, dropped blocks read as dropped, random ranges succeed exactly when all their blocks are kept; a damaged chunk only
fails its own blocks; a forged mask bit fails that block; a foreign key, a changed signature, header or hash table stop
ors_open; the UEFI descriptor parses and its forgeries are refused. With --store/--key the same full read runs on a real
store (every block of every window, counts against the store header). Nothing here touches a phone.
"""
import argparse
import hashlib
import importlib.util
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEVICE = HERE.parent
PACKAGE = DEVICE / 'package'
DECODER = ['lzfse_decode_base.c', 'lzfse_fse.c', 'lzvn_decode_base.c']
BLOCK, CHUNK = 4096, 65536


def run(cmd, **kw):
    r = subprocess.run([str(c) for c in cmd], text=True, capture_output=True, **kw)
    if r.returncode:
        raise SystemExit(f'{" ".join(str(c) for c in cmd)}\n{r.stdout}{r.stderr}')
    return r


def build(vr, out):
    common = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-I', PACKAGE, '-I', PACKAGE / 'lzfse',
              '-I', vr / 'include', '-I', vr / 'tests']
    sources = [PACKAGE / 'OpoiosRootStore.c', PACKAGE / 'OpoiosLzfse.c', *[PACKAGE / 'lzfse' / s for s in DECODER],
               vr / 'src/verified_root.c', PACKAGE / 'OpoiosRootStoreTests.c']
    # The vendored decoder is Apple's code as it is: its own warnings are not ours to fix.
    lz = ['-Wno-error', '-w']
    objs = {}
    for flavour, flags in (('asan', ['-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all']),
                           ('fast', ['-O2', '-DNDEBUG'])):
        d = out / flavour
        d.mkdir(parents=True, exist_ok=True)
        objects = []
        for s in sources:
            o = d / (s.stem + '.o')
            extra = lz if s.parent.name == 'lzfse' else []
            run(['gcc', *common, *flags, *extra, '-c', s, '-o', o])
            objects.append(o)
        run(['gcc', *flags, *objects, '-lcrypto', '-o', d / 'ors-test'])
        objs[flavour] = d / 'ors-test'
    lib = out / 'liblzfse.so'
    run(['gcc', '-O2', '-shared', '-fPIC', '-w', *sorted((PACKAGE / 'lzfse').glob('*.c')), '-o', lib])
    return objs, lib


def load_store_builder(lib):
    os.environ['OPOIOS_LZFSE_LIB'] = str(lib)
    spec = importlib.util.spec_from_file_location('opoios_root_store', HERE / 'opoios-root-store.py')
    s = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = s
    spec.loader.exec_module(s)
    return s


class Signer:
    def __init__(self, d):
        self.d = d
        key, pub = d / 'key.pem', d / 'pub.pem'
        run(['openssl', 'genpkey', '-quiet', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', key])
        run(['openssl', 'pkey', '-in', key, '-pubout', '-out', pub])
        modulus = run(['openssl', 'rsa', '-pubin', '-in', pub, '-modulus', '-noout']).stdout.strip().split('=', 1)[1]
        self.key = key
        self.anchor = b'VROOTKEY' + bytes.fromhex(modulus) + b'\x01\x00\x01'
        (d / 'anchor.bin').write_bytes(self.anchor)

    def header(self, data, volume):
        hashes = b''.join(hashlib.sha256(data[i:i + BLOCK]).digest() for i in range(0, len(data), BLOCK))
        h = struct.pack('<8s4I2Q16s32s32s32sQ', b'VROOT01\0', 1, 160, 4096, 0, len(data), len(hashes) // 32, volume.bytes,
                        hashlib.sha256(data).digest(), hashlib.sha256(hashes).digest(), hashlib.sha256(self.anchor).digest(), 1)
        (self.d / 'h.bin').write_bytes(h)
        sig = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(self.key), str(self.d / 'h.bin')],
                             check=True, capture_output=True).stdout
        return h + sig


def image(seed, layout):
    rng = random.Random(seed)
    out = bytearray()
    for kind in layout:
        if kind == 'random':
            out += rng.randbytes(CHUNK)
        elif kind == 'text':
            line = b'OPOIOS stage 4 RAM root store %d\n' % rng.randrange(1000)
            out += (line * (CHUNK // len(line) + 1))[:CHUNK]
        elif kind == 'zero':
            out += bytes(CHUNK)
        elif kind == 'mixed':
            for i in range(CHUNK // BLOCK):
                out += bytes(BLOCK) if i % 3 == 0 else rng.randbytes(BLOCK) if i % 3 == 1 else b'y' * BLOCK
        else:
            out += rng.randbytes(kind)
    return bytes(out)


def parse(stdout):
    rows = {}
    for line in stdout.splitlines():
        m = re.match(r'WINDOW (\S+) uuid (\S+) blocks (\d+) ok (\d+) dropped (\d+) damaged (\d+) mismatched (\d+) '
                     r'random ok (\d+) fail (\d+) wrong (\d+) .* (AGREES|DIFFERS)$', line)
        if m:
            k = ('uuid', 'blocks', 'ok', 'dropped', 'damaged', 'mismatched', 'rok', 'rfail', 'rwrong', 'verdict')
            vals = [m.group(2)] + [int(m.group(i)) for i in range(3, 11)] + [m.group(11)]
            rows[m.group(1)] = dict(zip(k, vals))
    return rows


def check(cond, what):
    print(('ok    ' if cond else 'FAIL  ') + what)
    if not cond:
        raise SystemExit(1)


def synthetic(tool, S, d):
    signer = Signer(d)
    os_img = image(2, ['random', 'text', 'zero', 'mixed', 'text', 'text', 'random', 5000])
    sys_img = image(3, ['text', 'random', 'mixed', 'text'])
    (d / 'os.img').write_bytes(os_img)
    (d / 'sys.img').write_bytes(sys_img)
    u_os, u_sys = uuid.UUID('E3F4AED0-4454-4D5B-833C-E27E99C4F67B'), uuid.UUID('8B599D21-9ABD-4050-8BA2-C61349890BED')
    n_os = (len(os_img) + BLOCK - 1) // BLOCK
    mask = bytearray(n_os)
    dropped = [1, 2, 17, 31, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 100, n_os - 1]
    for b in dropped:
        mask[b] = 1
    wins = [S.Window('OS', d / 'os.img', S.Manifest(signer.header(os_img, u_os), signer.anchor), bytes(mask)),
            S.Window('SystemOS', d / 'sys.img', S.Manifest(signer.header(sys_img, u_sys), signer.anchor),
                     bytes((len(sys_img) + BLOCK - 1) // BLOCK))]
    records, size = S.build(wins, d / 'store.bin', jobs=0, log=lambda *a: None)
    kinds = (records[0]['zero_chunks'], records[0]['raw_chunks'], records[0]['lzfse_chunks'])
    check(kinds[2] >= 4, f'synthetic store: OS chunks zero/raw/LZFSE {kinds}, real LZFSE chunks present')
    S.verify(d / 'store.bin', {'OS': signer.anchor, 'SystemOS': signer.anchor}, log=lambda *a: None)
    args = ['--image', f'OS={d / "os.img"}', '--image', f'SystemOS={d / "sys.img"}', '--slots', '3', '--random', '3000']
    r = subprocess.run([str(tool), 'check', str(d / 'store.bin'), str(d / 'anchor.bin'), *args], text=True, capture_output=True)
    rows = parse(r.stdout)
    check(r.returncode == 0 and rows['OS']['verdict'] == 'AGREES' and rows['SystemOS']['verdict'] == 'AGREES',
          f'every block reads back equal to the image (3-slot cache), dropped = {rows["OS"]["dropped"]} '
          f'of {len(dropped)}, random ranges {rows["OS"]["rok"]} ok / {rows["OS"]["rfail"]} refused as expected')
    check(rows['OS']['uuid'] == str(u_os).upper(), 'window UUID comes from the signed envelope')
    # The kernel's access: two extents around a hole and mapping windows, here at sizes that put chunks across windows and
    # the extent split inside the chunk data (the mapper refuses any mapping across the hole or past the store).
    size = (d / 'store.bin').stat().st_size
    data_split = (size - 3 * 4096 - 5 * 4096) // 4096 * 4096
    for window, split in ((64 << 20, None), (4096, None), (0x11000, data_split), (0x11000, 0x3000 + 2 * 4096)):
        extra = ['--window', str(window)] + (['--split', str(split)] if split else [])
        r = subprocess.run([str(tool), 'check', str(d / 'store.bin'), str(d / 'anchor.bin'), *args, *extra], text=True,
                           capture_output=True)
        rows = parse(r.stdout)
        maps = next((l for l in r.stdout.splitlines() if l.startswith('MAPS')), '')
        ok = r.returncode == 0 and rows and all(v['verdict'] == 'AGREES' for v in rows.values())
        if not ok and 'OPEN' in r.stdout and 'OPEN ok' not in r.stdout:
            # A split inside the header, envelopes or tables cannot be pinned: ors_open must say so (cannot map).
            ok = 'OPEN cannot map' in r.stdout and split is not None and split < 64 * 1024
        check(ok, f'window {window} bytes, split {split or "default"}: {maps or r.stdout.strip()[-120:]}')

    def mutate(name, fn):
        data = bytearray((d / 'store.bin').read_bytes())
        fn(data)
        (d / name).write_bytes(bytes(data))
        return subprocess.run([str(tool), 'check', str(d / name), str(d / 'anchor.bin'), *args], text=True, capture_output=True)

    st = S.Store(d / 'store.bin', {'OS': signer.anchor, 'SystemOS': signer.anchor})
    w = st.windows['OS']
    off, stored, present, kind = S.ENTRY.unpack_from(w['table'], 1 * 16)
    st.close()
    r = mutate('damaged.bin', lambda b: b.__setitem__(w['data_offset'] + off + stored // 2,
                                                      b[w['data_offset'] + off + stored // 2] ^ 0x5a))
    rows = parse(r.stdout)
    lost = w['present_blocks'] - rows['OS']['ok']
    check(kind == 2 and 0 < lost <= bin(present).count('1') and rows['OS']['damaged'] >= lost and
          rows['OS']['mismatched'] == 0 and rows['OS']['rwrong'] == 0 and rows['SystemOS']['verdict'] == 'AGREES',
          f'a damaged LZFSE chunk: {lost} of its {bin(present).count("1")} kept blocks fail, no wrong byte is returned, '
          f'every other block still reads')

    def forge(b):
        o, s2, p, k = S.ENTRY.unpack_from(b, w['table_offset'])
        S.ENTRY.pack_into(b, w['table_offset'], o, s2, p | 1 << 2, k)
    rows = parse(mutate('forged.bin', forge).stdout)
    check(rows['OS']['damaged'] == 1 and rows['OS']['dropped'] == len(dropped) - 1,
          'a forged present bit on a dropped block reads as damaged (zeros do not match the signed hash)')

    other = Signer(d / 'other') if (d / 'other').mkdir() is None else None
    r = subprocess.run([str(tool), 'check', str(d / 'store.bin'), str(d / 'other/anchor.bin')], text=True, capture_output=True)
    check('OPEN key' in r.stdout, 'a foreign trusted key stops ors_open (key)')
    r = mutate('sig.bin', lambda b: b.__setitem__(w['manifest_offset'] + 200, b[w['manifest_offset'] + 200] ^ 1))
    check('OPEN signature' in r.stdout, 'a changed signature stops ors_open (signature)')
    r = mutate('hashes.bin', lambda b: b.__setitem__(w['manifest_offset'] + 544 + 40, b[w['manifest_offset'] + 544 + 40] ^ 1))
    check('OPEN hash table' in r.stdout, 'a changed block hash stops ors_open (hash table)')
    r = mutate('header.bin', lambda b: b.__setitem__(64 + 40, b[64 + 40] ^ 1))
    check('OPEN format' in r.stdout, 'a changed store header stops ors_open (format)')

    def descriptor(store_bytes, extents, payload=(0xBA013E000, 0x12C00000), tweak=None):
        body = struct.pack('<8sIIQ32sII', b'OPRSTORE', 1, 144, store_bytes, hashlib.sha256(b'store').digest(), len(extents), 0)
        for base, n in list(extents) + [(0, 0)] * (2 - len(extents)):
            body += struct.pack('<QQ', base, n)
        body += struct.pack('<QQ', *payload)
        body = bytearray(body)
        if tweak:
            tweak(body)
        page = bytes(body) + hashlib.sha256(bytes(body)).digest()
        return page + bytes(4096 - len(page))

    # The phone's layout (run 3-2): the region after its 64 KiB descriptor area, around the 300 MiB ABL payload.
    good = [(0xA00010000, 0x1A012E000), (0xBACD3E000, 0x4D081000)]
    cases = [('good', descriptor(8045268992, good), 'DESCRIPTOR ok store 8045268992 extents 2 0xa00010000+0x1a012e000 '
                                                    '0xbacd3e000+0x4d081000'),
             ('overlap', descriptor(8045268992, [(0xA00010000, 0x200000000), good[1]]), 'DESCRIPTOR format'),
             ('small', descriptor(0x1A012E000 + 0x4D081000 + 1, good), 'DESCRIPTOR format'),
             ('version', descriptor(8045268992, good, tweak=lambda b: b.__setitem__(8, 2)), 'DESCRIPTOR format')]
    for name, page, want in cases:
        (d / f'desc-{name}.bin').write_bytes(page)
        out = subprocess.run([str(tool), 'descriptor', str(d / f'desc-{name}.bin')], text=True, capture_output=True).stdout
        check(out.startswith(want), f'descriptor {name}: {out.strip()}')
    page = bytearray(descriptor(8045268992, good))
    page[20] ^= 1
    (d / 'desc-sum.bin').write_bytes(bytes(page))
    out = subprocess.run([str(tool), 'descriptor', str(d / 'desc-sum.bin')], text=True, capture_output=True).stdout
    check(out.startswith('DESCRIPTOR format'), 'descriptor with a changed byte: its SHA-256 refuses it')


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--verified-root', required=True, type=Path)
    ap.add_argument('--store', type=Path)
    ap.add_argument('--key', type=Path)
    ap.add_argument('--keep', type=Path, help='work directory to keep (default: a temporary one)')
    a = ap.parse_args()
    work = a.keep or Path(tempfile.mkdtemp(prefix='ors-'))
    work.mkdir(parents=True, exist_ok=True)
    try:
        tools, lib = build(a.verified_root.resolve(), work / 'build')
        print(f'built ors-test (ASan/UBSan and -O2) and {lib.name}')
        S = load_store_builder(lib)
        (work / 'synthetic').mkdir(exist_ok=True)
        synthetic(tools['asan'], S, work / 'synthetic')
        if a.store:
            r = subprocess.run([str(tools['fast']), 'check', str(a.store), str(a.key), '--slots', '256', '--random', '20000'],
                               text=True, capture_output=True)
            print(r.stdout.strip())
            check(r.returncode == 0, f'full read of {a.store.name}: every block of every window as the header says')
        print('ALL PASS')
    finally:
        if not a.keep:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    main()
