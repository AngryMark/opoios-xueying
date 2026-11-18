/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/*
 * OPOIOS: the RAM root store (stage 4 path 1). Portable C: the kernel driver (OpoiosRootStoreDisk.cpp) and the host
 * checks (OpoiosRootStoreTests.c) share it.
 *
 * UEFI (OPOIOS XueyingUsbRamDxe) receives the store over USB into the reserved RAM above the XNU window and, once its
 * SHA-256 matches, writes a descriptor ("OPRSTORE") at the start of that region: the store's size and digest and the one
 * or two physical extents it occupies around the boot payload. The store (format OPROOT01, written by UniXNU-xueying
 * scripts/opoios-root-store.py, whose header describes it in full) holds the original OS and SystemOS disk images as
 * 64 KiB chunks, zero, raw or LZFSE, with the blocks of dropped files left out, and each image's signed VerifiedRoot
 * envelope. Nothing in the store is trusted: ors_open authenticates every envelope with the key compiled into the
 * kernel, and ors_read checks each 4 KiB block against its envelope before a byte of it is copied out. A dropped block
 * reads as ORS_DROPPED, a damaged one as ORS_DAMAGED; both are EIO to the file system.
 */
#ifndef OPOIOS_ROOT_STORE_H
#define OPOIOS_ROOT_STORE_H
#include <stddef.h>
#include <stdint.h>
#include "verified_root.h"
#ifdef __cplusplus
extern "C" {
#endif

#define ORS_BLOCK 4096u
#define ORS_CHUNK 65536u
#define ORS_PER (ORS_CHUNK / ORS_BLOCK)
#define ORS_MAX_WINDOWS 4u
#define ORS_HEADER_BYTES 4096u
#define ORS_DESCRIPTOR_BYTES 144u
#define ORS_REGION_BASE 0xA00000000ull        /* xueyingPkg "OPOIOS Root Store" region; the descriptor is its first bytes */

enum ors_status { ORS_OK = 0, ORS_FORMAT, ORS_KEY, ORS_SIGNATURE, ORS_HASH_TABLE, ORS_RANGE, ORS_DROPPED, ORS_DAMAGED,
                  ORS_MAP };

/* How the reader reaches the store. The kernel cannot map the whole store at once (phone run store1, 2026-11-18: the
 * one 7.5 GiB mapping failed), so the store is never addressed as one block of memory:
 * - pin: a view of [offset, offset + length) that stays valid while the store is open (the header, each window's
 *   envelope and chunk table); NULL when it cannot be mapped;
 * - copy: copies [offset, offset + length) to dst (chunk data, through the caller's mapping windows); 0 on success. */
struct ors_access {
    void *context;
    const uint8_t *(*pin)(void *context, uint64_t offset, uint64_t length);
    int (*copy)(void *context, uint64_t offset, void *dst, uint64_t length);
};

struct ors_extent { uint64_t base, bytes; };
struct ors_descriptor {
    uint64_t store_bytes;
    uint8_t store_sha256[32];
    unsigned extent_count;
    struct ors_extent extent[2];
    uint64_t payload_base, payload_bytes;
};
/* The 144-byte UEFI descriptor: signature, version, size, its own SHA-256, extents (4 KiB aligned, ordered, disjoint,
 * covering at least the store). */
int ors_descriptor_parse(const uint8_t *page, size_t bytes, const struct vr_crypto *crypto, struct ors_descriptor *out);

/* The store in physical memory: its extents and the platform's mapper, behind an ors_access.
 * - pin maps [offset, offset + length) of the store as its own mapping, kept until ors_phys_release; it must lie in one
 *   extent (the header, envelopes and tables are at the start of the store, far inside the first one);
 * - copy goes through up to ORS_PHYS_WINDOWS mapping windows of window_bytes, each inside one extent, replaced least
 *   recently used first.
 * map returns the virtual address of physical [phys, phys + length) (page aligned) and a handle for unmap, or NULL. */
#define ORS_PHYS_WINDOWS 8u
#define ORS_PHYS_PINS 16u
struct ors_phys_window { uint64_t phys, length; const uint8_t *va; void *handle; uint32_t used; };
struct ors_phys {
    uint64_t store_bytes, window_bytes;
    unsigned extent_count;
    struct ors_extent extent[2];
    void *context;
    const uint8_t *(*map)(void *context, uint64_t phys, uint64_t length, void **handle);
    void (*unmap)(void *context, void *handle);
    struct ors_phys_window window[ORS_PHYS_WINDOWS];
    void *pin[ORS_PHYS_PINS];
    unsigned pins;
    uint32_t clock;
    uint64_t maps, unmaps, map_failures;
};
/* window_bytes: a multiple of 4 KiB. Returns ORS_FORMAT for a layout that does not cover store_bytes. */
int ors_phys_init(struct ors_phys *phys, const struct ors_descriptor *descriptor, uint64_t window_bytes, void *context,
                  const uint8_t *(*map)(void *, uint64_t, uint64_t, void **), void (*unmap)(void *, void *));
void ors_phys_access(struct ors_phys *phys, struct ors_access *out);
void ors_phys_release(struct ors_phys *phys);

struct ors_window {
    char name[17];
    uint8_t volume_uuid[16];                 /* from the authenticated envelope */
    uint64_t image_bytes, block_count, chunk_count;
    uint64_t present_blocks, dropped_blocks;
    const uint8_t *envelope;                 /* authenticated by vr_open */
    uint64_t envelope_bytes;
    const uint8_t *table;                    /* chunk table: untrusted */
    uint64_t data_offset, data_bytes;        /* chunk data (store offsets): untrusted */
    struct vr_view vr;
};
struct ors_store {
    struct ors_access access;
    uint64_t bytes;
    unsigned window_count;
    struct ors_window window[ORS_MAX_WINDOWS];
};
/* access/bytes: the store, immutable while in use. key: the trusted anchor (VR_KEY_BYTES). */
int ors_open(struct ors_store *store, const struct ors_access *access, uint64_t bytes, const uint8_t *key,
             const struct vr_crypto *crypto);
int ors_find(const struct ors_store *store, const char *name);      /* window index, or -1 */
void ors_uuid_string(const uint8_t uuid[16], char out[37]);          /* upper case, as IOMedia "UUID" */

/* Decoded chunks are cached; the reader is not thread-safe (the driver serializes it). */
struct ors_slot {
    uint64_t key;                            /* window << 56 | chunk; UINT64_MAX = empty */
    uint32_t used;
    uint16_t present, verified;
    uint8_t *data;                           /* ORS_CHUNK bytes */
};
struct ors_stats { uint64_t reads, bytes, decodes, hits, verified, dropped, damaged; };
struct ors_reader {
    void *scratch;                           /* ors_scratch_bytes(): the LZFSE state, then the packed chunk */
    uint8_t *packed;                         /* a stored LZFSE chunk, copied out of the store before it is decoded */
    struct ors_slot *slot;
    unsigned slots;
    uint32_t clock;
    struct ors_stats stats;
};
size_t ors_scratch_bytes(void);
/* memory: count * ORS_CHUNK bytes for the slots. */
void ors_reader_init(struct ors_reader *reader, void *scratch, struct ors_slot *slots, uint8_t *memory, unsigned count);
/* Image bytes [offset, offset + length) of window `window` into dst; on failure dst holds nothing unverified. */
int ors_read(struct ors_reader *reader, const struct ors_store *store, unsigned window, uint64_t offset, void *dst,
             uint64_t length, const struct vr_crypto *crypto);
const char *ors_status_name(int status);

#ifdef __cplusplus
}
#endif
#endif
