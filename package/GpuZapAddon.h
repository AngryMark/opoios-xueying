// SPDX-License-Identifier: BSD-2-Clause-Patent
// OPOIOS (xueying): find one file in the GPU addon the payload carries (scripts/make-gpu-addon.py, "NGPUADD2"; the loader hands it
// to the kernel as /chosen/memory-map/GpuAddon). The kernel is built in public CI, which never sees this phone's Adreno ZAP image;
// the owner's PC packs it into the addon as firmware/a740_zap.mbn, and GpuPowerProbe.cpp takes it from there when its embedded ZAP
// is empty. The checks are those of the kernel's own addon writer (UniXNU patches/xnu-12377/zzy-native-gpu-addon-mount.patch):
// the whole addon must be well formed before any entry is used. Header only, portable C; host-tested by GpuZapAddonTests.c.
//
// Layout, little endian: "NGPUADD2", u32 count, u32 0, u64 total bytes; per file u32 path bytes (with its NUL, 2..160), u32 mode
// (permission bits only), u64 size, u64 compressed size, the path padded to 8 bytes, the zlib stream padded to 8 bytes.
#ifndef OPOIOS_GPU_ZAP_ADDON_H
#define OPOIOS_GPU_ZAP_ADDON_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define GZA_E_HEADER (-31)   // no addon magic, a count of 0 or above 4096, or a total that is not the blob's size
#define GZA_E_ENTRY (-32)    // an entry runs past the blob, or its path, mode or sizes are not what the kernel accepts
#define GZA_E_TRAILING (-33) // bytes after the last entry
#define GZA_E_MISSING (-34)  // well formed, but no entry has that path

static inline uint32_t gza_u32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static inline uint64_t gza_u64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }

// Finds `name` in the addon of `bytes` bytes. On success *packed points at its zlib stream of *packed_bytes bytes, *size is the
// file's size once inflated, and 0 is returned; otherwise a GZA_E_* code and the outputs are untouched.
static inline int gza_find(const uint8_t *addon, uint64_t bytes, const char *name, const uint8_t **packed, uint64_t *packed_bytes,
                           uint64_t *size)
{
    if (!addon || !name || bytes < 24 || memcmp(addon, "NGPUADD2", 8)) return GZA_E_HEADER;
    const uint32_t count = gza_u32(addon + 8);
    if (gza_u64(addon + 16) != bytes || !count || count > 4096) return GZA_E_HEADER;
    const size_t want = strlen(name) + 1;
    const uint8_t *found = 0;
    uint64_t found_packed = 0, found_size = 0, at = 24;
    for (uint32_t i = 0; i < count; ++i) {
        if (bytes - at < 24) return GZA_E_ENTRY;
        const uint32_t name_bytes = gza_u32(addon + at), mode = gza_u32(addon + at + 4);
        const uint64_t file_size = gza_u64(addon + at + 8), stream = gza_u64(addon + at + 16);
        at += 24;
        const uint64_t name_padded = (name_bytes + 7ull) & ~7ull, stream_padded = (stream + 7ull) & ~7ull;
        if (name_bytes < 2 || name_bytes > 160 || bytes - at < name_padded) return GZA_E_ENTRY;
        const char *path = (const char *)(addon + at);
        if (path[name_bytes - 1] || strnlen(path, name_bytes) != name_bytes - 1 || path[0] == '/' || (mode & ~0777u) ||
            file_size > 0x7fffffffull || !stream || stream > 0x7fffffffull || bytes - at - name_padded < stream_padded)
            return GZA_E_ENTRY;
        for (uint32_t k = 0; k + 1 < name_bytes - 1; ++k)
            if (path[k] == '.' && path[k + 1] == '.') return GZA_E_ENTRY;
        if (!found && name_bytes == want && !memcmp(path, name, want)) {
            found = addon + at + name_padded;
            found_packed = stream;
            found_size = file_size;
        }
        at += name_padded + stream_padded;
    }
    if (at != bytes) return GZA_E_TRAILING;
    if (!found) return GZA_E_MISSING;
    *packed = found;
    *packed_bytes = found_packed;
    *size = found_size;
    return 0;
}
#endif
