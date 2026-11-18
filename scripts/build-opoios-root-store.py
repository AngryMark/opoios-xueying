#!/usr/bin/env python3
"""OPOIOS: build the RAM root store driver (stage 4 path 1, step 5) as build/opoios-root-store/libOpoiosRootStore.a.

An archive step after build-sheng-source-storage.py, run in the tree (board.toml [kernel] archives); the defconfig
force-loads the archive (CONFIG_XNU_EXTRA_LD_ARCHIVES). It compiles, with the kernel's own compile records as
build-sheng-source-storage.py does:
- package/OpoiosRootStoreDisk.cpp: the window disks, an IOBlockStorageDevice subclass. Its static constructor is
  taken out of __mod_init_func and globalized, so SourceStorage.cpp registers the class (opoios-ram-root=2) between
  preModLoad and postModLoad, after the source IOBlockStorageDevice it derives from;
- package/OpoiosRootStore.c (store, windows, verified reads) and package/OpoiosLzfse.c with the vendored decoder
  (package/lzfse: lzfse_decode_base.c, lzfse_fse.c, lzvn_decode_base.c; Apple's code as it is, its warnings off).
VerifiedRoot (verified_root.c, the XNU crypto adapter) and the trusted anchor verified_root_key come from
libShengSourceStorage.a, so the store is authenticated with the same policy key as the root policies.
"""
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

LZFSE_DECODER = ('lzfse_decode_base.c', 'lzfse_fse.c', 'lzvn_decode_base.c')


def helper(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    tree = Path(os.environ.get('UNIXNU_TREE') or Path.cwd()).resolve()
    # The device repository first (CI sets UNIXNU_DEVICE), then the tree's installed kit, then next to this script.
    candidates = []
    if os.environ.get('UNIXNU_DEVICE'):
        candidates.append(Path(os.environ['UNIXNU_DEVICE']) / 'package')
    candidates += [tree / 'kits/sheng', Path(__file__).resolve().parents[1] / 'package']
    package = next((d for d in candidates if (d / 'OpoiosRootStoreDisk.cpp').is_file()), None)
    if not package:
        raise SystemExit('OpoiosRootStoreDisk.cpp not found in ' + ', '.join(map(str, candidates)))
    headers = tree / 'build/sheng-source-storage/headers/include'
    if not (headers / 'IOKit/storage/IOBlockStorageDevice.h').is_file():
        raise SystemExit(f'{headers}: run build-sheng-source-storage.py first (it prepares the IOStorageFamily headers)')
    verified_root = tree / 'kits/VerifiedRoot/include'
    # As build-sheng-source-storage.py: the source storage runtime is arm64e only (unixnu exports both variables).
    os.environ.setdefault('UNIXNU_XNU_ARCH', 'arm64e')
    if os.environ['UNIXNU_XNU_ARCH'] != 'arm64e':
        raise SystemExit('the RAM root store driver is built for arm64e kernels only')
    build = helper('source_compile', tree / 'scripts/build-sheng-source-drivers.py')
    target = helper('source_target', tree / 'scripts/kernel_target.py')
    out = tree / 'build/opoios-root-store'
    out.mkdir(parents=True, exist_ok=True)
    obj = tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
    cpp = json.loads((obj / 'iokit/DEVELOPMENT/IOPlatformExpert.cpo.json').read_text().strip().rstrip(','))
    c = json.loads((obj / 'osfmk/DEVELOPMENT/startup.o.json').read_text().strip().rstrip(','))
    # As build-sheng-source-storage.py: the source osfmk ahead of the exported headers (its kalloc type macros).
    includes = ['-I', str(headers), '-I', str(verified_root), '-I', str(package), '-I', str(package / 'lzfse'),
                '-I', str(tree / '.cache/xnu-work/osfmk')]
    # package/lzfse-kernel: <assert.h> and <stdlib.h> for the decoder, which the kernel's C environment lacks.
    shim = ['-I', str(package / 'lzfse-kernel')]
    vendored = ['-Wno-error', '-w', '-DNDEBUG', *shim]
    # Newer clang (the PC toolchain of 2026-11-18) flags XNU's own kalloc type macros (kt_zearly) under -Wextra; the
    # kernel's headers are not ours to change. Older clang does not know the group, hence the unknown-option guard.
    kernel = ['-Wno-unknown-warning-option', '-Wno-missing-designated-field-initializers']
    sources = [(package / 'OpoiosRootStoreDisk.cpp', cpp, kernel), (package / 'OpoiosRootStore.c', c, kernel),
               (package / 'OpoiosLzfse.c', c, kernel + ['-DNDEBUG', *shim])]
    sources += [(package / 'lzfse' / name, c, vendored) for name in LZFSE_DECODER]
    objcopy = shutil.which('llvm-objcopy') or '/opt/homebrew/opt/llvm/bin/llvm-objcopy'
    objects, inputs = [], {}
    for source, record, extra in sources:
        output = out / (source.stem + '.o')
        command = build.compile_command(record, source, output, includes, extra)
        result = subprocess.run(command, cwd=record['directory'], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (out / (source.stem + '.command.json')).write_text(json.dumps(command, indent=2) + '\n')
        (out / (source.stem + '.log')).write_text(result.stdout)
        if result.returncode:
            raise SystemExit(f'{source.name}:\n{result.stdout[-6000:]}')
        target.check_object(output.read_bytes(), source.name)
        if source.name == 'OpoiosRootStoreDisk.cpp':
            late = output.with_suffix('.late.o')
            subprocess.run([objcopy, '--remove-section=__DATA,__mod_init_func',
                            f'--globalize-symbol=__GLOBAL__sub_I_{source.name}', output, late], check=True)
            output = late
        objects.append(output)
        inputs[str(source)] = sha(source)
    for header in ('OpoiosRootStore.h', 'lzfse/lzfse_internal.h', 'lzfse/lzfse_fse.h', 'lzfse/lzvn_decode_base.h'):
        inputs[str(package / header)] = sha(package / header)
    archive = out / 'libOpoiosRootStore.a'
    archive.unlink(missing_ok=True)
    subprocess.run(['xcrun', 'ar', 'rcs', archive, *objects], check=True)
    report = dict(archive=str(archive), archive_sha256=sha(archive), sources=inputs, package=str(package),
                  target=target.TRIPLE, runtime_qualified=False)
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(archive)


if __name__ == '__main__':
    main()
