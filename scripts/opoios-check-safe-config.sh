#!/usr/bin/env bash
# Refuses a UniXNU device configuration or payload that would let XNU write to UFS.
# Run on board.toml, unixnu.toml, defconfig, boot-argument files — or a whole directory —
# before every `fastboot boot` of a new build.
#
# Why: in the reference sheng configuration XNU writes the persistent Data store and the
# boot log to the END of `userdata`. On the OnePlus Open that area holds encrypted Android
# data. Both writers are off unless their boot arguments are given, and both also require an
# iOS root manifest in userdata (absent on our phone) — this check is the third guard.
#
# Usage: scripts/check-safe-config.sh <file-or-dir> [...]

set -u
[ $# -ge 1 ] || { echo "usage: $0 <file-or-dir> [...]"; exit 2; }

# boot arguments / options that open a write path to storage
PATTERNS=(
  'data-persist=[12]'          # UniXNU persistent Data store at the end of userdata (also sheng-data-persist)
  '\blog=1'                    # UniXNU BootLog writer (last 32 MiB of userdata), also sheng-log=1
  'log-reserve='               # only meaningful with the writers above
  'native-ufs-root=1'          # root mounted from UFS (ShengUfs)
  'native-source-storage=1'    # root image read from the UFS partition
  '^\[userdata\]'              # board section that describes a flashed iOS partition
  '&ufs(phy)? *\{ *status *= *"okay"'  # device tree enabling the UFS controller for the kernel
  'ufs_write=1|ufs-write=1'    # HakiOS-style UFS writes
  'var_store=1'                # HakiOS /private/var on UFS
  'persistent_data *= *true'   # UniXNU board option for the persistent Data store
  'fastboot +(flash|erase|format|-w|set_active)'  # flash commands in scripts or reports
  'LOG_PARTITION'              # HakiOS loader log writer (logdump partition)
)

bad=0
for target in "$@"; do
  for p in "${PATTERNS[@]}"; do
    hits=$(grep -rnIE --exclude-dir=.git -e "$p" "$target" 2>/dev/null)
    if [ -n "$hits" ]; then
      echo "[!] write path pattern: $p"
      echo "$hits" | sed 's/^/    /' | head -20
      bad=1
    fi
  done
done

if [ $bad -ne 0 ]; then
  echo "[x] UNSAFE: remove these before booting this build on the daily phone."
  exit 1
fi
echo "[+] No storage write paths found in: $*"
