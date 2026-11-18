#!/usr/bin/env python3
"""OPOIOS: the phone's tweaks of a packed Data seed (stage 4 path 1, step 6), and its volume UUID.

    opoios-seed-tweaks.py BASE.dbr OUTPUT.dbr          (macOS, as root: hdiutil, file owners)
    opoios-seed-tweaks.py --uuid SEED.dbr              (anywhere: print the seed's one APFS volume UUID)

BASE is a DBRDISK1 packed APFS seed from UniXNU scripts/make-data-seed.py (aston's recipe: --skip-setup with
UNIXNU_SEED_FIRST_BOOT_MIGRATION=1, so the first boot runs the data migration that makes the system apps' containers).
It is expanded to a raw image, attached on this Mac, and com.apple.springboard in /private/var/mobile/Library/Preferences
gets SBDisableAutoDim, SBDontDimOrLockOnAC and SBDisableIdleSleep: the phone has no touch yet, and without them SpringBoard
turns the display off and locks about 30 seconds after it starts (UniXNU seed-data-skip-setup.py --no-auto-dim does the
same, but it also writes com.apple.migration, which would skip that migration). The image is packed again. The volume UUID
is unchanged, which this script checks: the kernel binds the Data volume by it (CONFIG_XNU_OWNER_DATA_VOLUME_UUID).
Nothing else changes; BASE is not modified.
"""
import importlib.util
import json
import os
import plistlib
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

NO_DIM = {'SBDisableAutoDim': True, 'SBDontDimOrLockOnAC': True, 'SBDisableIdleSleep': True}


def packer():
    """drivers/DarwinBoot/Test/packed_ramdisk.py of the UniXNU tree (UNIXNU_TREE, or ../UniXNU next to this repository)."""
    tree = Path(os.environ.get('UNIXNU_TREE') or Path(__file__).resolve().parents[2] / 'UniXNU')
    path = tree / 'drivers/DarwinBoot/Test/packed_ramdisk.py'
    spec = importlib.util.spec_from_file_location('packed_ramdisk', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def volume_uuid(blob, pr):
    """The one APFS volume UUID of a packed seed, as UniXNU's unixnu/runtime.py seed_uuid reads it."""
    _, extents = pr.regions(blob)
    found = set()
    for _, data in extents:
        for at in range(0, len(data), 4096):
            block = data[at:at + 4096]
            if block[32:36] == b'APSB':
                found.add(str(uuid.UUID(bytes=bytes(block[240:256]))).upper())
    if len(found) != 1:
        raise SystemExit(f'require exactly one APFS volume UUID in the seed, found {sorted(found)}')
    return found.pop()


def main():
    pr = packer()
    if len(sys.argv) == 3 and sys.argv[1] == '--uuid':
        print(volume_uuid(Path(sys.argv[2]).read_bytes(), pr))
        return 0
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    base, output = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    if output.exists():
        raise SystemExit(f'refuse to overwrite {output}')
    blob = base.read_bytes()
    before = volume_uuid(blob, pr)
    logical, extents = pr.regions(blob)
    with tempfile.TemporaryDirectory(prefix='opoios-seed-', dir=str(output.parent)) as td:
        raw = Path(td) / 'seed.raw'
        with raw.open('wb') as f:
            f.truncate(logical)
            for offset, data in extents:
                f.seek(offset)
                f.write(data)
        mount = Path(td) / 'mount'
        mount.mkdir()
        attached = plistlib.loads(subprocess.check_output(
            ['hdiutil', 'attach', '-imagekey', 'diskimage-class=CRawDiskImage', '-nobrowse', '-owners', 'off',
             '-mountpoint', str(mount), '-plist', str(raw)]))
        device = attached['system-entities'][0]['dev-entry']
        try:
            prefs = mount / 'mobile/Library/Preferences'
            if not prefs.is_dir():
                raise SystemExit('the seed has no /mobile/Library/Preferences: not a make-data-seed.py seed?')
            path = prefs / 'com.apple.springboard.plist'
            content = plistlib.loads(path.read_bytes()) if path.is_file() else {}
            content.update(NO_DIM)
            path.write_bytes(plistlib.dumps(content, fmt=plistlib.FMT_BINARY))  # an existing file keeps its owner and mode
            path.chmod(0o644)
            migration = (prefs / 'com.apple.migration.plist').is_file()
        finally:
            subprocess.run(['hdiutil', 'detach', device], check=True)
        if raw.open('rb').read(36)[32:36] != b'NXSB':
            raise SystemExit('the edited image is no APFS container any more')
        metadata = pr.pack(raw, output)
    after = volume_uuid(output.read_bytes(), pr)
    if after != before:
        raise SystemExit(f'volume UUID changed: {before} -> {after}')
    report = dict(base=str(base), output=str(output), volume_uuid=after, springboard=sorted(NO_DIM),
                  migration_marker_present=migration, packed=metadata)
    print(json.dumps(report, indent=2, default=str))
    return 0


if __name__ == '__main__':
    sys.exit(main())
