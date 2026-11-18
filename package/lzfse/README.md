# lzfse (vendored)

Apple's reference LZFSE/LZVN codec, BSD-3-Clause (see LICENSE), from https://github.com/lzfse/lzfse at commit
e634ca58b4821d9f3d560cdc6df5dec02ffc93fd (2017-05-22, the last commit; tag lzfse-1.0 is 88e2d27), files of `src/`
unmodified except that the command-line tool `lzfse_main.c` is left out.

OPOIOS uses it for the RAM root store (package/OpoiosRootStore.c): the kernel links only the decoder
(lzfse_decode_base.c, lzfse_fse.c, lzvn_decode_base.c; the buffer entry point is OpoiosRootStore.c's, because
lzfse_decode.c falls back to malloc), and the host checks (scripts/check-opoios-root-store.py) build the whole codec.
