#!/usr/bin/env python3
"""OPOIOS: measure decrypted iOS root images (raw APFS containers) for the RAM budget of stage 4.

    python3 scripts/opoios-measure-root.py --out DIR NAME=IMAGE [NAME=IMAGE ...]

For each image: its size, the 4 KiB and 16 KiB pages that hold any nonzero byte (what a packed RAM disk that omits zero pages
would keep), and the run of nonzero extents. On macOS the image is also attached read-only (hdiutil, raw disk image class) to
report the APFS volumes' used capacity, the space taken per directory (du, allocated blocks, so APFS-compressed files count
with their compressed size) and the largest files.

Writes DIR/report.txt (all numbers and paths) and DIR/summary.md (totals only). Nothing from the images themselves is copied:
the report holds sizes and path names only. The workflow seals the report before upload anyway.
"""
import argparse
import os
import plistlib
import subprocess
import sys
import tempfile
from pathlib import Path

CHUNK = 64 << 20
GIB = 1 << 30


def nonzero_pages(path):
    """One pass: nonzero 16 KiB pages, nonzero 4 KiB pages, total 16 KiB pages, nonzero 16 KiB extents (first, count)."""
    big, small = 16384, 4096
    zero_big, zero_small = bytes(big), bytes(small)
    n16, n4, total, extents, run_start = 0, 0, 0, [], None
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            if len(chunk) % big:
                chunk += bytes(big - len(chunk) % big)
            for at in range(0, len(chunk), big):
                block = chunk[at:at + big]
                if block != zero_big:
                    n16 += 1
                    n4 += sum(block[i:i + small] != zero_small for i in range(0, big, small))
                    if run_start is None:
                        run_start = total
                elif run_start is not None:
                    extents.append((run_start, total - run_start))
                    run_start = None
                total += 1
    if run_start is not None:
        extents.append((run_start, total - run_start))
    return n16, n4, total, extents


def attach(image, mount):
    out = subprocess.check_output(['hdiutil', 'attach', '-imagekey', 'diskimage-class=CRawDiskImage', '-readonly',
                                   '-nobrowse', '-owners', 'off', '-mountpoint', str(mount), '-plist', str(image)])
    entities = plistlib.loads(out)['system-entities']
    return [e['dev-entry'] for e in entities], [e['mount-point'] for e in entities if e.get('mount-point')]


def apfs_usage(devices):
    """Used capacity of every APFS volume in the containers of the attached devices."""
    info = plistlib.loads(subprocess.check_output(['diskutil', 'apfs', 'list', '-plist']))
    rows = []
    for container in info.get('Containers', []):
        stores = {s.get('DeviceIdentifier') for s in container.get('PhysicalStores', [])}
        if not any(Path(d).name in stores for d in devices):
            continue
        rows.append(f"container {container.get('ContainerReference')}: size {container.get('CapacityCeiling', 0) / GIB:.2f} GiB, "
                    f"free {container.get('CapacityFree', 0) / GIB:.2f} GiB")
        for volume in container.get('Volumes', []):
            rows.append(f"  volume {volume.get('Name')!r} roles {volume.get('Roles')} sealed {volume.get('Sealed')}: "
                        f"in use {volume.get('CapacityInUse', 0) / GIB:.3f} GiB")
    return rows


def du(root, depth):
    out = subprocess.run(['du', '-x', '-k', '-d', str(depth), str(root)], capture_output=True, text=True)
    rows = []
    for line in out.stdout.splitlines():
        kib, _, path = line.partition('\t')
        rel = os.path.relpath(path, root)
        rows.append((int(kib), '/' if rel == '.' else '/' + rel))
    rows.sort(key=lambda r: -r[0])
    return rows, out.stderr.count('\n')


def largest(root, count):
    files = []
    root_dev = os.lstat(root).st_dev
    for current, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if os.lstat(os.path.join(current, d)).st_dev == root_dev]
        for name in names:
            p = os.path.join(current, name)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if not os.path.islink(p):
                files.append((st.st_blocks * 512, st.st_size, '/' + os.path.relpath(p, root)))
    files.sort(key=lambda f: -f[0])
    return files[:count], sum(f[0] for f in files), len(files)


def measure(name, image, report, summary):
    size = image.stat().st_size
    report.append(f'=== {name}: {image.name}, {size} bytes = {size / GIB:.3f} GiB')
    n16, n4, total, extents = nonzero_pages(image)
    totals = {'size': size, 4096: n4 * 4096, 16384: n16 * 16384}
    report.append(f'   4 KiB pages: {n4} of {total * 4} nonzero = {n4 * 4096 / GIB:.3f} GiB ({100 * n4 / max(total * 4, 1):.1f} %)')
    report.append(f'  16 KiB pages: {n16} of {total} nonzero = {n16 * 16384 / GIB:.3f} GiB ({100 * n16 / max(total, 1):.1f} %), '
                  f'{len(extents)} nonzero extents')
    biggest_gap = max(((extents[i + 1][0] - (extents[i][0] + extents[i][1])) for i in range(len(extents) - 1)), default=0)
    tail = total - (extents[-1][0] + extents[-1][1]) if extents else total
    report.append(f'  largest zero gap between extents: {biggest_gap * 16384 / GIB:.3f} GiB, zero tail {tail * 16384 / GIB:.3f} GiB')
    row = f'| {name} | {size / GIB:.2f} GiB | {totals[4096] / GIB:.2f} GiB | {totals[16384] / GIB:.2f} GiB |'
    if sys.platform != 'darwin':
        report.append('  (not macOS: no APFS mount)')
        summary.append(row + ' – |')
        return totals
    with tempfile.TemporaryDirectory() as tmp:
        mount = Path(tmp) / 'mnt'
        mount.mkdir()
        try:
            devices, mounts = attach(image, mount)
        except (subprocess.CalledProcessError, KeyError, ValueError) as error:
            report.append(f'  attach failed: {error}')
            summary.append(row + ' attach failed |')
            return totals
        try:
            report.append(f'  attached {devices}, mounted {mounts}')
            report.extend('  ' + r for r in apfs_usage(devices))
            root = Path(mounts[0]) if mounts else mount
            files, allocated, nfiles = largest(root, 60)
            totals['files'] = allocated
            report.append(f'  files: {nfiles}, allocated {allocated / GIB:.3f} GiB')
            rows, errors = du(root, 3)
            report.append(f'  du -d 3 (KiB allocated), {errors} unreadable entries:')
            report.extend(f'    {kib:>10}  {path}' for kib, path in rows if kib >= 20 * 1024)
            report.append('  largest files (allocated / logical bytes):')
            report.extend(f'    {a:>12} {s:>12}  {p}' for a, s, p in files)
        finally:
            for device in devices[:1]:
                subprocess.run(['hdiutil', 'detach', device, '-force'], check=False, capture_output=True)
    summary.append(row + f' {totals["files"] / GIB:.2f} GiB |')
    return totals


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('images', nargs='+', help='NAME=PATH of a raw image')
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    report, summary = [], ['| image | raw | nonzero 4 KiB | nonzero 16 KiB | files (allocated) |',
                           '| --- | --- | --- | --- | --- |']
    grand = {'size': 0, 4096: 0, 16384: 0}
    for item in args.images:
        name, _, path = item.partition('=')
        totals = measure(name, Path(path), report, summary)
        for key in grand:
            grand[key] += totals[key]
    summary.append(f'| all | {grand["size"] / GIB:.2f} GiB | {grand[4096] / GIB:.2f} GiB | {grand[16384] / GIB:.2f} GiB | |')
    (args.out / 'report.txt').write_text('\n'.join(report) + '\n')
    (args.out / 'summary.md').write_text('\n'.join(summary) + '\n')
    print('\n'.join(summary))


if __name__ == '__main__':
    sys.exit(main())
