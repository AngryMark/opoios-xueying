#!/usr/bin/env bash
# OPOIOS: seal CI outputs so that nothing derived from Apple software leaves the runner in the clear.
#
#   bash scripts/opoios-ci-seal.sh <name> <base-dir> <out-dir> <path-or-glob relative to base-dir>...
#
# A pattern that starts with ? is optional (e.g. the prelink maps, which a successful build may not keep).
#
# The repository is public, so every artifact can be downloaded by anyone signed in to GitHub. The kernel (kernel.macho, the
# prelinked iPhone17,2 kernelcache's kexts), the reference kernels, the prelink maps and the build logs therefore go out only
# inside <name>.tar.gz.enc, encrypted to the owner's RSA key, the way OddlyLabs/unixnu-fuxi seals its boot image
# (.github/workflows/build.yml, "Encrypt the boot image"):
# - a fresh random 256-bit key per bundle; tar.gz encrypted with openssl enc -aes-256-cbc -pbkdf2 under that key;
# - the key encrypted with RSA-OAEP (SHA-256) to ci/opoios-artifact-recipient.pem, the owner's public key; the private key
#   never exists outside the owner's PC (~/opoios/secrets/ci-artifact.key), so no repository secret is needed or exposed;
# - inside the tar, SHA256SUMS of the members (checked after decryption); next to it, <name>.sha256 of the encrypted files.
# Decrypt on the PC with OPOIOS scripts/ci-artifact.sh. Missing members fail the step unless SEAL_ALLOW_MISSING=1.
set -euo pipefail
name=$1; base=$2; out=$3; shift 3
here=$(cd "$(dirname "$0")/.." && pwd)
recipient=${SEAL_RECIPIENT:-$here/ci/opoios-artifact-recipient.pem}
openssl=${OPENSSL:-openssl}
"$openssl" version | grep -q '^OpenSSL 3' || { echo "::error::need OpenSSL 3 (got: $("$openssl" version))"; exit 1; }
[ -s "$recipient" ] || { echo "::error::no recipient key $recipient: nothing is uploaded unencrypted"; exit 1; }
"$openssl" pkey -pubin -in "$recipient" -noout 2>/dev/null || { echo "::error::$recipient is not a public key"; exit 1; }

stage=$(mktemp -d "${RUNNER_TEMP:-/tmp}/seal.XXXXXX")
trap 'rm -rf "$stage"' EXIT
list=$stage/members
: > "$list"
(
  cd "$base"
  shopt -s nullglob dotglob
  for pattern in "$@"; do
    optional=0
    case $pattern in \?*) optional=1; pattern=${pattern#\?} ;; esac
    matched=0
    for f in $pattern; do
      [ -f "$f" ] || continue
      printf '%s\n' "$f" >> "$list"; matched=1
    done
    if [ "$matched" = 0 ]; then
      if [ "$optional" = 1 ] || [ "${SEAL_ALLOW_MISSING:-0}" = 1 ]; then echo "::warning::$name: nothing matches $pattern"
      else echo "::error::$name: nothing matches $pattern"; exit 1; fi
    fi
  done
)
if [ ! -s "$list" ]; then
  [ "${SEAL_ALLOW_MISSING:-0}" = 1 ] && { echo "::warning::$name: no files to seal"; exit 0; }
  echo "::error::$name: no files to seal"; exit 1
fi
(cd "$base" && tr '\n' '\0' < "$list" | xargs -0 shasum -a 256) > "$stage/SHA256SUMS"
# Two passes (bsdtar on the runner, GNU tar on the PC): the members, then SHA256SUMS at the top of the bundle.
tar -cf "$stage/bundle.tar" -C "$base" -T "$list"
tar -rf "$stage/bundle.tar" -C "$stage" SHA256SUMS
gzip -9 -n "$stage/bundle.tar"

mkdir -p "$out"
"$openssl" rand -hex 32 > "$stage/key"
"$openssl" enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -in "$stage/bundle.tar.gz" -out "$out/$name.tar.gz.enc" \
  -pass "file:$stage/key"
"$openssl" pkeyutl -encrypt -pubin -inkey "$recipient" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256 -in "$stage/key" -out "$out/$name.key.enc"
(cd "$out" && shasum -a 256 "$name.tar.gz.enc" "$name.key.enc" > "$name.sha256")
echo "sealed $name: $(wc -l < "$list" | tr -d ' ') files, recipient $("$openssl" pkey -pubin -in "$recipient" -outform DER | shasum -a 256 | cut -c1-16)"
sed 's/^/  /' "$stage/SHA256SUMS"
