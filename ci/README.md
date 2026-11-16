# Sealed CI artifacts

`opoios-kernel.yml` uploads nothing derived from Apple software in the clear. `scripts/opoios-ci-seal.sh` encrypts each
bundle with a fresh AES-256 key and encrypts that key with RSA-OAEP (SHA-256) to `opoios-artifact-recipient.pem`, the
owner's public key. The private key exists only on the owner's PC; the repository has no secret.

`opoios-artifact-recipient.pem` is added by the owner (OPOIOS `scripts/ci-artifact.sh keygen`). Until it is here, the
workflow stops at its safety gate before building anything.
