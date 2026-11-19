// SPDX-License-Identifier: BSD-2-Clause-Patent
// Host test of GpuZapAddon.h: an NGPUADD2 addon built here with zlib (as scripts/make-gpu-addon.py and scripts/opoios-gpu-addon.py
// write it), the ZAP entry found and inflated byte for byte, and every rule of the kernel's addon writer refused. Build with -lz.
#include "GpuZapAddon.h"
#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>

#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); exit(1); } } while (0)

static uint8_t blob[1 << 16];
static size_t used;
static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static void put64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }
static void begin(void) { memset(blob, 0, sizeof blob); memcpy(blob, "NGPUADD2", 8); used = 24; }
// Appends one entry; returns the offset of its header.
static size_t add(const char *path, uint32_t mode, const uint8_t *data, size_t size)
{
    uLongf packed = compressBound(size);
    uint8_t *z = malloc(packed);
    CHECK(z && compress(z, &packed, data, size) == Z_OK);
    const size_t at = used, name = strlen(path) + 1, name_pad = (name + 7) & ~(size_t)7, z_pad = (packed + 7) & ~(size_t)7;
    put32(blob + at, (uint32_t)name);
    put32(blob + at + 4, mode);
    put64(blob + at + 8, size);
    put64(blob + at + 16, packed);
    memcpy(blob + at + 24, path, name);
    memcpy(blob + at + 24 + name_pad, z, packed);
    used = at + 24 + name_pad + z_pad;
    free(z);
    return at;
}
static void finish(uint32_t count) { put32(blob + 8, count); put64(blob + 16, used); }

int main(void)
{
    uint8_t zap[12088], plist[300], lib[5000];
    for (size_t i = 0; i < sizeof zap; ++i) zap[i] = (uint8_t)(i * 7 + 3);
    memcpy(zap, "\x7f" "ELF", 4);
    memset(plist, 'p', sizeof plist);
    for (size_t i = 0; i < sizeof lib; ++i) lib[i] = (uint8_t)(i ^ (i >> 3));
    const char *Z = "firmware/a740_zap.mbn";

    begin();
    add("addons/NativeAdrenoMetal.bundle/Info.plist", 0644, plist, sizeof plist);
    add("addons/NativeAdrenoMetal.bundle/NativeAdrenoMetal", 0755, lib, sizeof lib);
    const size_t zat = add(Z, 0444, zap, sizeof zap);
    finish(3);
    const uint8_t *packed = (const uint8_t *)1;
    uint64_t packed_bytes = 77, size = 88;
    CHECK(gza_find(blob, used, Z, &packed, &packed_bytes, &size) == 0);
    CHECK(size == sizeof zap && packed == blob + zat + 24 + 24 && packed_bytes == (uint64_t)(blob[zat + 16] | blob[zat + 17] << 8));
    uint8_t out[sizeof zap];
    uLongf out_bytes = sizeof out;
    CHECK(uncompress(out, &out_bytes, packed, packed_bytes) == Z_OK && out_bytes == sizeof zap && !memcmp(out, zap, sizeof zap));
    // A name that is only a prefix or a suffix of a path is not that path.
    const uint8_t *keep = packed;
    CHECK(gza_find(blob, used, "firmware/a740_zap", &packed, &packed_bytes, &size) == GZA_E_MISSING && packed == keep);
    CHECK(gza_find(blob, used, "a740_zap.mbn", &packed, &packed_bytes, &size) == GZA_E_MISSING);
    // Header: magic, count, total.
    uint8_t save[64];
    memcpy(save, blob, 24);
    blob[0] = 'X'; CHECK(gza_find(blob, used, Z, &packed, &packed_bytes, &size) == GZA_E_HEADER); memcpy(blob, save, 24);
    put32(blob + 8, 0); CHECK(gza_find(blob, used, Z, &packed, &packed_bytes, &size) == GZA_E_HEADER); memcpy(blob, save, 24);
    put32(blob + 8, 5000); CHECK(gza_find(blob, used, Z, &packed, &packed_bytes, &size) == GZA_E_HEADER); memcpy(blob, save, 24);
    CHECK(gza_find(blob, used - 8, Z, &packed, &packed_bytes, &size) == GZA_E_HEADER);   // total says more than given
    CHECK(gza_find(blob, 10, Z, &packed, &packed_bytes, &size) == GZA_E_HEADER);
    CHECK(gza_find(NULL, used, Z, &packed, &packed_bytes, &size) == GZA_E_HEADER);
    // A count larger than the entries: the next header runs past the blob.
    put32(blob + 8, 4); CHECK(gza_find(blob, used, Z, &packed, &packed_bytes, &size) == GZA_E_ENTRY); memcpy(blob, save, 24);
    // A count smaller than the entries: trailing bytes.
    put32(blob + 8, 2); CHECK(gza_find(blob, used, Z, &packed, &packed_bytes, &size) == GZA_E_TRAILING); memcpy(blob, save, 24);
    // Entry rules, each on the ZAP entry (the last one), restored after.
    memcpy(save, blob + zat, 64);
    blob[zat + 24] = '/'; CHECK(gza_find(blob, used, Z, &packed, &packed_bytes, &size) == GZA_E_ENTRY); memcpy(blob + zat, save, 64);
    memcpy(blob + zat + 24, "fi../a7", 7); CHECK(gza_find(blob, used, Z, &packed, &packed_bytes, &size) == GZA_E_ENTRY);
    memcpy(blob + zat, save, 64);
    put32(blob + zat + 4, 04755); CHECK(gza_find(blob, used, Z, &packed, &packed_bytes, &size) == GZA_E_ENTRY); memcpy(blob + zat, save, 64);
    put32(blob + zat, 1); CHECK(gza_find(blob, used, Z, &packed, &packed_bytes, &size) == GZA_E_ENTRY); memcpy(blob + zat, save, 64);
    put32(blob + zat, 200); CHECK(gza_find(blob, used, Z, &packed, &packed_bytes, &size) == GZA_E_ENTRY); memcpy(blob + zat, save, 64);
    blob[zat + 24 + 21] = 'x';   // the path's NUL gone
    CHECK(gza_find(blob, used, Z, &packed, &packed_bytes, &size) == GZA_E_ENTRY); memcpy(blob + zat, save, 64);
    put32(blob + zat, 10);       // a NUL inside the declared path length
    CHECK(gza_find(blob, used, Z, &packed, &packed_bytes, &size) == GZA_E_ENTRY); memcpy(blob + zat, save, 64);
    put64(blob + zat + 16, 0); CHECK(gza_find(blob, used, Z, &packed, &packed_bytes, &size) == GZA_E_ENTRY); memcpy(blob + zat, save, 64);
    put64(blob + zat + 16, 1ull << 40); CHECK(gza_find(blob, used, Z, &packed, &packed_bytes, &size) == GZA_E_ENTRY);
    memcpy(blob + zat, save, 64);
    put64(blob + zat + 8, 1ull << 33); CHECK(gza_find(blob, used, Z, &packed, &packed_bytes, &size) == GZA_E_ENTRY);
    memcpy(blob + zat, save, 64);
    // A stream that runs past the blob.
    put64(blob + zat + 16, used); CHECK(gza_find(blob, used, Z, &packed, &packed_bytes, &size) == GZA_E_ENTRY); memcpy(blob + zat, save, 64);
    // Restored: found again, outputs as at the start.
    CHECK(gza_find(blob, used, Z, &packed, &packed_bytes, &size) == 0 && size == sizeof zap);
    // A path repeated: the first entry is the one used.
    begin();
    add(Z, 0444, zap, sizeof zap);
    add(Z, 0444, plist, sizeof plist);
    finish(2);
    CHECK(gza_find(blob, used, Z, &packed, &packed_bytes, &size) == 0 && size == sizeof zap);
    printf("gpu-zap-addon: find, inflate and the kernel writer's rules hold\n");
    return 0;
}
