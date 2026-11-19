#!/usr/bin/env python3
"""OPOIOS (xueying): put this phone's Adreno ZAP image into the GPU addon the payload carries.

  opoios-gpu-addon.py OUTPUT --zap FILE [--base ADDON]

The kernel is built in public CI, which never sees the ZAP (it is the phone maker's signed image, kept on the owner's PC in
~/opoios/secrets/gpu). This adds it to an addon as firmware/a740_zap.mbn (mode 0444): to ADDON from UniXNU's scripts/make-gpu-addon.py
(the Metal plugin), or alone without --base. package/GpuPowerProbe.cpp takes it from /chosen/memory-map/GpuAddon when the kernel's
embedded ZAP is empty; with gpu-addon=1 the kernel also writes it to /private/var/ngpu/firmware/ like every addon file (Data lives
in RAM). The image must match the pin in scripts/data/xueying-gpu-inputs.json (size and SHA-256), the same pin package/GpuPowerBoard.h
carries; the output is checked against the rules of the kernel's addon writer (package/GpuZapAddon.h) before it is written.

Layout, little endian: "NGPUADD2", u32 count, u32 0, u64 total bytes; per file u32 path bytes (with its NUL), u32 mode, u64 size,
u64 compressed size, the path padded to 8 bytes, the zlib stream padded to 8 bytes."""
import argparse
import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN = ROOT / 'scripts/data/xueying-gpu-inputs.json'
NAME = 'firmware/a740_zap.mbn'


def pad(data):
    return data + bytes(-len(data) % 8)


def entries(blob):
    """The (path, mode, size, stream) entries of an addon, checked as package/GpuZapAddon.h checks them."""
    if len(blob) < 24 or blob[:8] != b'NGPUADD2':
        raise ValueError('not an NGPUADD2 addon')
    count, zero, total = struct.unpack_from('<IIQ', blob, 8)
    if total != len(blob) or not count or count > 4096 or zero:
        raise ValueError(f'bad addon header: count {count}, total {total} for {len(blob)} bytes')
    at, out = 24, []
    for _ in range(count):
        if len(blob) - at < 24:
            raise ValueError('entry header past the end')
        name_bytes, mode, size, packed = struct.unpack_from('<IIQQ', blob, at)
        at += 24
        name_pad, packed_pad = (name_bytes + 7) & ~7, (packed + 7) & ~7
        raw = blob[at:at + name_bytes]
        if not 2 <= name_bytes <= 160 or len(blob) - at < name_pad or raw[-1:] != b'\0' or b'\0' in raw[:-1]:
            raise ValueError('bad entry path')
        path = raw[:-1].decode()
        if path.startswith('/') or '..' in path or mode & ~0o777 or size > 0x7fffffff or not packed or packed > 0x7fffffff \
                or len(blob) - at - name_pad < packed_pad:
            raise ValueError(f'bad entry {path!r}')
        stream = blob[at + name_pad:at + name_pad + packed]
        out.append((path, mode, size, stream))
        at += name_pad + packed_pad
    if at != len(blob):
        raise ValueError('bytes after the last entry')
    return out


def pack(files):
    body = b''
    for path, mode, size, stream in files:
        name = path.encode() + b'\0'
        body += struct.pack('<IIQQ', len(name), mode, size, len(stream)) + pad(name) + pad(stream)
    return b'NGPUADD2' + struct.pack('<IIQ', len(files), 0, 24 + len(body)) + body


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('output', type=Path)
    ap.add_argument('--zap', type=Path, required=True, help='this phone\'s a740_zap.mbn (~/opoios/secrets/gpu/a740_zap.mbn)')
    ap.add_argument('--base', type=Path, help='an addon from scripts/make-gpu-addon.py to add the ZAP to')
    args = ap.parse_args()
    pin = json.loads(PIN.read_text())['firmware']['files'][NAME]
    zap = args.zap.read_bytes()
    digest = hashlib.sha256(zap).hexdigest()
    if len(zap) != pin['bytes'] or digest != pin['sha256']:
        sys.exit(f'{args.zap}: {len(zap)} bytes, sha256 {digest}; the pin wants {pin["bytes"]}, {pin["sha256"]}')
    if zap[:4] != b'\x7fELF':
        sys.exit(f'{args.zap}: not an ELF image')
    files = [e for e in entries(args.base.read_bytes()) if e[0] != NAME] if args.base else []
    files.append((NAME, 0o444, len(zap), zlib.compress(zap, 9)))
    blob = pack(files)
    check = {path: (size, stream) for path, _, size, stream in entries(blob)}
    size, stream = check[NAME]
    if size != len(zap) or zlib.decompress(stream) != zap:
        sys.exit('the packed ZAP does not read back')
    args.output.write_bytes(blob)
    print(f'{args.output}: {len(files)} files, {len(blob)} bytes; {NAME} {len(zap)} bytes sha256 {digest}')


if __name__ == '__main__':
    main()
