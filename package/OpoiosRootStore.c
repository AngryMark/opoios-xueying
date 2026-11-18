/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* OPOIOS RAM root store: descriptor, store header, authenticated windows and verified reads (see OpoiosRootStore.h). */
#include "OpoiosRootStore.h"
#include <string.h>

/* OpoiosLzfse.c: the reference decoder behind a buffer entry point that needs no allocator. */
size_t ors_lzfse_scratch_bytes(void);
size_t ors_lzfse_decode(uint8_t *dst, size_t dst_size, const uint8_t *src, size_t src_size, void *scratch);

static uint64_t le(const uint8_t *p, unsigned n)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

static int same(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

/* offset + bytes inside [0, limit) without overflow */
static int inside(uint64_t offset, uint64_t bytes, uint64_t limit)
{
    return offset <= limit && bytes <= limit - offset;
}

const char *ors_status_name(int status)
{
    switch (status) {
    case ORS_OK: return "ok";
    case ORS_FORMAT: return "format";
    case ORS_KEY: return "key";
    case ORS_SIGNATURE: return "signature";
    case ORS_HASH_TABLE: return "hash table";
    case ORS_RANGE: return "range";
    case ORS_DROPPED: return "dropped block";
    case ORS_DAMAGED: return "damaged block";
    default: return "?";
    }
}

int ors_descriptor_parse(const uint8_t *p, size_t bytes, const struct vr_crypto *crypto, struct ors_descriptor *out)
{
    static const uint8_t magic[8] = {'O', 'P', 'R', 'S', 'T', 'O', 'R', 'E'};
    uint8_t digest[32];
    if (!out) return ORS_FORMAT;
    memset(out, 0, sizeof(*out));
    if (!p || !crypto || !crypto->sha256 || bytes < ORS_DESCRIPTOR_BYTES || !same(p, magic, 8) || le(p + 8, 4) != 1 ||
        le(p + 12, 4) != ORS_DESCRIPTOR_BYTES || !crypto->sha256(p, 112, digest) || !same(digest, p + 112, 32))
        return ORS_FORMAT;
    struct ors_descriptor d;
    memset(&d, 0, sizeof(d));
    d.store_bytes = le(p + 16, 8);
    memcpy(d.store_sha256, p + 24, 32);
    d.extent_count = (unsigned)le(p + 56, 4);
    if (d.extent_count < 1 || d.extent_count > 2 || le(p + 60, 4) != 0 || d.store_bytes < ORS_HEADER_BYTES)
        return ORS_FORMAT;
    uint64_t total = 0, end = 0;
    for (unsigned i = 0; i < d.extent_count; ++i) {
        d.extent[i].base = le(p + 64 + 16 * i, 8);
        d.extent[i].bytes = le(p + 72 + 16 * i, 8);
        if (!d.extent[i].bytes || (d.extent[i].base & (ORS_BLOCK - 1)) || (d.extent[i].bytes & (ORS_BLOCK - 1)) ||
            d.extent[i].base < end || d.extent[i].bytes > UINT64_MAX - d.extent[i].base || total > UINT64_MAX - d.extent[i].bytes)
            return ORS_FORMAT;
        end = d.extent[i].base + d.extent[i].bytes;
        total += d.extent[i].bytes;
    }
    if (total < d.store_bytes) return ORS_FORMAT;
    d.payload_base = le(p + 96, 8);
    d.payload_bytes = le(p + 104, 8);
    *out = d;
    return ORS_OK;
}

void ors_uuid_string(const uint8_t uuid[16], char out[37])
{
    static const char hex[] = "0123456789ABCDEF";
    unsigned at = 0;
    for (unsigned i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out[at++] = '-';
        out[at++] = hex[uuid[i] >> 4];
        out[at++] = hex[uuid[i] & 15];
    }
    out[at] = 0;
}

int ors_find(const struct ors_store *store, const char *name)
{
    if (!store || !name) return -1;
    for (unsigned i = 0; i < store->window_count; ++i)
        if (!strcmp(store->window[i].name, name)) return (int)i;
    return -1;
}

int ors_open(struct ors_store *store, const uint8_t *base, uint64_t bytes, const uint8_t *key,
             const struct vr_crypto *crypto)
{
    static const uint8_t magic[8] = {'O', 'P', 'R', 'O', 'O', 'T', '0', '1'};
    uint8_t digest[32];
    if (!store) return ORS_FORMAT;
    memset(store, 0, sizeof(*store));
    if (!base || !key || !crypto || !crypto->sha256 || bytes < ORS_HEADER_BYTES) return ORS_FORMAT;
    const uint8_t *h = base;
    const unsigned count = (unsigned)le(h + 16, 4);
    if (!same(h, magic, 8) || le(h + 8, 4) != 1 || le(h + 12, 4) != ORS_HEADER_BYTES || le(h + 20, 4) != ORS_CHUNK ||
        le(h + 24, 8) != bytes || le(h + 32, 8) != 0 || count < 1 || count > ORS_MAX_WINDOWS ||
        !crypto->sha256(h, 4064, digest) || !same(digest, h + 4064, 32))
        return ORS_FORMAT;
    struct ors_store s;
    memset(&s, 0, sizeof(s));
    s.base = base;
    s.bytes = bytes;
    s.window_count = count;
    for (unsigned i = 0; i < count; ++i) {
        const uint8_t *r = h + 64 + 192 * i;
        struct ors_window *w = &s.window[i];
        unsigned length = 0;
        while (length < 16 && r[length]) ++length;
        if (!length) return ORS_FORMAT;
        for (unsigned j = 0; j < 16; ++j) {
            if (j < length && (r[j] < 0x21 || r[j] > 0x7e)) return ORS_FORMAT;
            if (j >= length && r[j]) return ORS_FORMAT;
        }
        memcpy(w->name, r, length);
        w->image_bytes = le(r + 32, 8);
        w->block_count = le(r + 40, 8);
        w->chunk_count = le(r + 48, 8);
        const uint64_t manifest = le(r + 56, 8), manifestBytes = le(r + 64, 8);
        const uint64_t table = le(r + 72, 8), tableBytes = le(r + 80, 8);
        const uint64_t data = le(r + 88, 8), dataBytes = le(r + 96, 8);
        w->present_blocks = le(r + 104, 8);
        w->dropped_blocks = le(r + 112, 8);
        if (!w->image_bytes || w->image_bytes > UINT64_MAX - ORS_CHUNK ||
            w->block_count != (w->image_bytes + ORS_BLOCK - 1) / ORS_BLOCK ||
            w->chunk_count != (w->image_bytes + ORS_CHUNK - 1) / ORS_CHUNK ||
            w->chunk_count > UINT64_MAX / 16 || tableBytes != w->chunk_count * 16 ||
            w->block_count > (UINT64_MAX - VR_HEADER_BYTES - VR_SIGNATURE_BYTES) / 32 ||
            manifestBytes != VR_HEADER_BYTES + VR_SIGNATURE_BYTES + w->block_count * 32 ||
            (manifest | table | data) % ORS_BLOCK || manifest < ORS_HEADER_BYTES || table < ORS_HEADER_BYTES ||
            data < ORS_HEADER_BYTES || !inside(manifest, manifestBytes, bytes) || !inside(table, tableBytes, bytes) ||
            !inside(data, dataBytes, bytes) || manifestBytes > SIZE_MAX)
            return ORS_FORMAT;
        for (unsigned j = 0; j < i; ++j)
            if (!strcmp(s.window[j].name, w->name)) return ORS_FORMAT;
        w->envelope = base + manifest;
        w->envelope_bytes = manifestBytes;
        w->table = base + table;
        w->data = base + data;
        w->data_bytes = dataBytes;
        switch (vr_open(w->envelope, (size_t)manifestBytes, key, 1, crypto, &w->vr)) {
        case VR_OK: break;
        case VR_KEY: return ORS_KEY;
        case VR_SIGNATURE: return ORS_SIGNATURE;
        case VR_HASH_TABLE: return ORS_HASH_TABLE;
        default: return ORS_FORMAT;
        }
        if (w->vr.image_bytes != w->image_bytes || w->vr.block_count != w->block_count) return ORS_FORMAT;
        memcpy(w->volume_uuid, w->vr.volume_uuid, 16);
    }
    *store = s;
    return ORS_OK;
}

size_t ors_scratch_bytes(void)
{
    return ors_lzfse_scratch_bytes();
}

void ors_reader_init(struct ors_reader *reader, void *scratch, struct ors_slot *slots, uint8_t *memory, unsigned count)
{
    memset(reader, 0, sizeof(*reader));
    reader->scratch = scratch;
    reader->slot = slots;
    reader->slots = count;
    for (unsigned i = 0; i < count; ++i) {
        memset(&slots[i], 0, sizeof(slots[i]));
        slots[i].key = UINT64_MAX;
        slots[i].data = memory + (size_t)i * ORS_CHUNK;
    }
}

/* The chunk in a cache slot, decoded but not yet verified (verification is per block, on first use). */
static int load(struct ors_reader *r, const struct ors_window *w, unsigned window, uint64_t chunk, struct ors_slot **out)
{
    const uint64_t key = (uint64_t)window << 56 | chunk;
    struct ors_slot *victim = &r->slot[0];
    for (unsigned i = 0; i < r->slots; ++i) {
        struct ors_slot *slot = &r->slot[i];
        if (slot->key == key) {
            slot->used = ++r->clock;
            ++r->stats.hits;
            *out = slot;
            return ORS_OK;
        }
        if (victim->key != UINT64_MAX && (slot->key == UINT64_MAX || slot->used < victim->used)) victim = slot;
    }
    const uint8_t *e = w->table + chunk * 16;
    const uint64_t offset = le(e, 8), stored = le(e + 8, 4);
    const unsigned present = (unsigned)le(e + 12, 2), kind = e[14];
    const uint64_t length = w->image_bytes - chunk * ORS_CHUNK < ORS_CHUNK ? w->image_bytes - chunk * ORS_CHUNK : ORS_CHUNK;
    const unsigned blocks = (unsigned)((length + ORS_BLOCK - 1) / ORS_BLOCK);
    victim->key = UINT64_MAX;
    if ((blocks < 16 && present >> blocks) || !inside(offset, stored, w->data_bytes)) return ORS_DAMAGED;
    if (kind == 0 && stored == 0) {
        memset(victim->data, 0, (size_t)length);
    } else if (kind == 1 && stored == length) {
        memcpy(victim->data, w->data + offset, (size_t)length);
    } else if (kind == 2 && stored > 0 && stored <= ORS_CHUNK * 2) {
        if (ors_lzfse_decode(victim->data, (size_t)length, w->data + offset, (size_t)stored, r->scratch) != length)
            return ORS_DAMAGED;
    } else {
        return ORS_DAMAGED;
    }
    victim->key = key;
    victim->present = (uint16_t)present;
    victim->verified = 0;
    victim->used = ++r->clock;
    ++r->stats.decodes;
    *out = victim;
    return ORS_OK;
}

int ors_read(struct ors_reader *r, const struct ors_store *store, unsigned window, uint64_t offset, void *dst,
             uint64_t length, const struct vr_crypto *crypto)
{
    if (!r || !store || window >= store->window_count || !dst || !crypto || !r->slots) return ORS_RANGE;
    const struct ors_window *w = &store->window[window];
    if (!inside(offset, length, w->image_bytes)) return ORS_RANGE;
    ++r->stats.reads;
    uint8_t *out = dst;
    while (length) {
        const uint64_t chunk = offset / ORS_CHUNK, start = chunk * ORS_CHUNK;
        const uint64_t chunkBytes = w->image_bytes - start < ORS_CHUNK ? w->image_bytes - start : ORS_CHUNK;
        const uint64_t at = offset - start, n = length < chunkBytes - at ? length : chunkBytes - at;
        struct ors_slot *slot = NULL;
        int status = load(r, w, window, chunk, &slot);
        if (status) {
            ++r->stats.damaged;
            return status;
        }
        for (unsigned i = (unsigned)(at / ORS_BLOCK); i <= (unsigned)((at + n - 1) / ORS_BLOCK); ++i) {
            if (!(slot->present >> i & 1)) {
                ++r->stats.dropped;
                return ORS_DROPPED;
            }
            if (slot->verified >> i & 1) continue;
            const uint64_t begin = (uint64_t)i * ORS_BLOCK;
            const size_t blockBytes = (size_t)(chunkBytes - begin < ORS_BLOCK ? chunkBytes - begin : ORS_BLOCK);
            if (vr_verify_block(&w->vr, chunk * ORS_PER + i, slot->data + begin, blockBytes, crypto) != VR_OK) {
                slot->key = UINT64_MAX;
                ++r->stats.damaged;
                return ORS_DAMAGED;
            }
            slot->verified |= (uint16_t)(1u << i);
            ++r->stats.verified;
        }
        memcpy(out, slot->data + at, (size_t)n);
        out += n;
        offset += n;
        length -= n;
        r->stats.bytes += n;
    }
    return ORS_OK;
}
