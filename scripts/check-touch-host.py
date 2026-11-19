#!/usr/bin/env python3
"""Host tests for the touch stack: GENI SPI register model, the Goodix Berlin core, board helpers.

aston: the reference board's Novatek protocol and touch-core cases are gone with its controller. OPOIOS (xueying): the
GT9966 is driven by kits/sheng/GoodixBerlin.c, tested against a model controller (GoodixBerlinTests.c); aston's S3910 core
is not built for this phone.
Run from a build tree (scripts/, drivers/QcomGeniSpi, kits/sheng). These are model tests; none touches hardware.
"""
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FLAGS = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1', '-fsanitize=address,undefined']
CASES = [
    ('geni-spi', ['drivers/QcomGeniSpi/Test/geni-spi.c', 'drivers/QcomGeniSpi/GeniSpi.c'], []),
    ('touch-board', ['kits/sheng/TouchBoardTests.c'], []),
    ('goodix-berlin', ['kits/sheng/GoodixBerlinTests.c', 'kits/sheng/GoodixBerlin.c'], []),
]

with tempfile.TemporaryDirectory() as tmp:
    for name, sources, args in CASES:
        exe = Path(tmp) / name
        subprocess.run([*FLAGS, *[str(ROOT / s) for s in sources], '-o', str(exe)], check=True)
        out = subprocess.run([str(exe), *args], check=True, capture_output=True, text=True).stdout.strip().splitlines()
        print(f'{name}: {out[-1]}')
print('PASS: touch host tests (register/chip models only)')
