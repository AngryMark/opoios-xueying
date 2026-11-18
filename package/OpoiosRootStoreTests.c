/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* Host check of OpoiosRootStore.c with VerifiedRoot's OpenSSL provider (built by scripts/check-opoios-root-store.py).
 *
 *   ors-test check STORE KEY [--slots N] [--random N] [--window BYTES] [--split BYTES] [--image NAME=PATH]...
 *       open the store with the trusted anchor KEY (395 bytes); read every 4 KiB block of every window through ors_read
 *       (ok, dropped or damaged; ok blocks equal to the image when one is given); then N random reads of 512-byte
 *       aligned ranges up to 256 KiB, each of which must succeed exactly when every block it touches did.
 *       The store is reached as the kernel reaches it, through ors_phys: two extents laid out as on the phone (the first
 *       --split bytes at 0xA00010000, a 300 MiB hole, the rest after it; default: the phone's 0x1A012E000, or half of a
 *       smaller store) and mapping windows of --window bytes (default 64 MiB). The mapper refuses any mapping that is
 *       not inside one extent, as a mapping across the hole would be wrong on the phone.
 *   ors-test descriptor FILE    parse a descriptor page and print it.
 * Output: one "WINDOW" line per window and a "TOTAL" line; exit 0 only when every count agrees with the store header. */
#include "OpoiosRootStore.h"
#include "openssl_provider.c"   /* its static `provider`: OpenSSL SHA-256 and RSA-3072 */
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static void *map_file(const char *path, uint64_t *bytes)
{
    int fd = open(path, O_RDONLY);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || st.st_size <= 0) { perror(path); exit(2); }
    void *p = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED) { perror("mmap"); exit(2); }
    *bytes = (uint64_t)st.st_size;
    return p;
}

static uint64_t rng_state = 0x4f504f494f53ull;
static uint64_t rng(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

/* Fake physical memory: the two extents of a descriptor map onto consecutive parts of the store file. */
struct fake_phys {
    const uint8_t *store;
    struct ors_descriptor d;
    uint64_t live, refused;
};

static const uint8_t *fake_map(void *context, uint64_t phys, uint64_t length, void **handle)
{
    struct fake_phys *f = context;
    uint64_t before = 0;
    if ((phys & (ORS_BLOCK - 1)) || (length & (ORS_BLOCK - 1)) || !length) { ++f->refused; return NULL; }
    for (unsigned i = 0; i < f->d.extent_count; ++i) {
        const struct ors_extent *e = &f->d.extent[i];
        if (phys >= e->base && phys - e->base <= e->bytes && length <= e->bytes - (phys - e->base)) {
            /* Bytes past the store's end inside the last extent read as the file would not have them: refuse those. */
            if (before + (phys - e->base) + length > f->d.store_bytes) { ++f->refused; return NULL; }
            ++f->live;
            *handle = (void *)(uintptr_t)(phys | 1);
            return f->store + before + (phys - e->base);
        }
        before += e->bytes;
    }
    ++f->refused;
    return NULL;
}

static void fake_unmap(void *context, void *handle)
{
    struct fake_phys *f = context;
    if (!((uintptr_t)handle & 1) || !f->live) { fprintf(stderr, "bad unmap\n"); exit(3); }
    --f->live;
}

static int descriptor(const char *path)
{
    uint64_t bytes = 0;
    const uint8_t *p = map_file(path, &bytes);
    struct ors_descriptor d;
    int status = ors_descriptor_parse(p, (size_t)bytes, &provider, &d);
    if (status) {
        printf("DESCRIPTOR %s\n", ors_status_name(status));
        return 1;
    }
    printf("DESCRIPTOR ok store %" PRIu64 " extents %u", d.store_bytes, d.extent_count);
    for (unsigned i = 0; i < d.extent_count; ++i)
        printf(" %#" PRIx64 "+%#" PRIx64, d.extent[i].base, d.extent[i].bytes);
    printf(" payload %#" PRIx64 "+%#" PRIx64 "\n", d.payload_base, d.payload_bytes);
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc >= 3 && !strcmp(argv[1], "descriptor")) return descriptor(argv[2]);
    if (argc < 4 || strcmp(argv[1], "check")) {
        fprintf(stderr, "usage: ors-test check STORE KEY [--slots N] [--random N] [--image NAME=PATH]... | descriptor FILE\n");
        return 2;
    }
    unsigned slots = 64, randoms = 2000;
    uint64_t window = 64ull << 20, split = 0;
    const char *imageName[ORS_MAX_WINDOWS] = {0}, *imagePath[ORS_MAX_WINDOWS] = {0};
    unsigned images = 0;
    for (int i = 4; i < argc; ++i) {
        if (!strcmp(argv[i], "--slots") && i + 1 < argc) slots = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--random") && i + 1 < argc) randoms = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--window") && i + 1 < argc) window = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--split") && i + 1 < argc) split = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--image") && i + 1 < argc && images < ORS_MAX_WINDOWS) {
            char *spec = argv[++i], *eq = strchr(spec, '=');
            if (!eq) return 2;
            *eq = 0;
            imageName[images] = spec;
            imagePath[images++] = eq + 1;
        } else return 2;
    }
    uint64_t storeBytes = 0, keyBytes = 0;
    const uint8_t *base = map_file(argv[2], &storeBytes);
    const uint8_t *key = map_file(argv[3], &keyBytes);
    if (keyBytes != VR_KEY_BYTES) { fprintf(stderr, "key is %" PRIu64 " bytes\n", keyBytes); return 2; }
    /* The phone's layout (run 3-2): 0xA00010000 + 0x1A012E000, the 300 MiB ABL payload, then the rest. */
    struct fake_phys fake = {.store = base};
    if (!split) split = storeBytes > 0x1A012E000ull ? 0x1A012E000ull : (storeBytes / 2) & ~(uint64_t)(ORS_BLOCK - 1);
    fake.d.store_bytes = storeBytes;
    fake.d.extent_count = 2;
    fake.d.extent[0] = (struct ors_extent){0xA00010000ull, split};
    /* As on the phone, the last extent runs past the store (to the region's end); ors_phys must not map that part. */
    fake.d.extent[1] = (struct ors_extent){0xA00010000ull + split + 0x12C00000ull,
                                           ((storeBytes - split + ORS_BLOCK - 1) & ~(uint64_t)(ORS_BLOCK - 1)) + (64u << 20)};
    struct ors_phys phys;
    if (ors_phys_init(&phys, &fake.d, window, &fake, fake_map, fake_unmap)) { printf("PHYS format\n"); return 1; }
    struct ors_access access;
    ors_phys_access(&phys, &access);
    struct ors_store store;
    int status = ors_open(&store, &access, storeBytes, key, &provider);
    if (status) {
        printf("OPEN %s\n", ors_status_name(status));
        return 1;
    }
    printf("OPEN ok %u windows, split %#" PRIx64 ", mapping window %" PRIu64 " bytes\n", store.window_count, split, window);
    void *scratch = malloc(ors_scratch_bytes());
    struct ors_slot *slot = calloc(slots, sizeof(*slot));
    uint8_t *memory = malloc((size_t)slots * ORS_CHUNK);
    if (!scratch || !slot || !memory) return 2;
    struct ors_reader reader;
    ors_reader_init(&reader, scratch, slot, memory, slots);
    int failed = 0;
    uint64_t totalOk = 0, totalDropped = 0, totalDamaged = 0;
    uint8_t block[ORS_BLOCK], *big = malloc(256 * 1024);
    for (unsigned wi = 0; wi < store.window_count; ++wi) {
        const struct ors_window *w = &store.window[wi];
        const uint8_t *image = NULL;
        uint64_t imageBytes = 0;
        for (unsigned j = 0; j < images; ++j)
            if (!strcmp(imageName[j], w->name)) image = map_file(imagePath[j], &imageBytes);
        if (image && imageBytes != w->image_bytes) { printf("IMAGE %s size differs\n", w->name); return 1; }
        uint8_t *state = calloc((size_t)w->block_count, 1);     /* 1 ok, 2 dropped, 3 damaged */
        uint64_t ok = 0, dropped = 0, damaged = 0, mismatched = 0;
        for (uint64_t b = 0; b < w->block_count; ++b) {
            const uint64_t at = b * ORS_BLOCK;
            const uint64_t n = w->image_bytes - at < ORS_BLOCK ? w->image_bytes - at : ORS_BLOCK;
            status = ors_read(&reader, &store, wi, at, block, n, &provider);
            if (status == ORS_OK) {
                state[b] = 1, ++ok;
                if (image && memcmp(block, image + at, (size_t)n)) ++mismatched;
            } else if (status == ORS_DROPPED) state[b] = 2, ++dropped;
            else state[b] = 3, ++damaged;
        }
        uint64_t randomOk = 0, randomFail = 0, randomWrong = 0;
        for (unsigned k = 0; k < randoms && big; ++k) {
            const uint64_t sectors = w->image_bytes / 512;
            if (!sectors) break;
            uint64_t first = rng() % sectors, count = 1 + rng() % 512;
            if (count > sectors - first) count = sectors - first;
            const uint64_t at = first * 512, n = count * 512;
            int expect = ORS_OK;
            for (uint64_t b = at / ORS_BLOCK; b <= (at + n - 1) / ORS_BLOCK; ++b)
                if (state[b] != 1) expect = -1;
            status = ors_read(&reader, &store, wi, at, big, n, &provider);
            if (status == ORS_OK) {
                ++randomOk;
                if (expect != ORS_OK || (image && memcmp(big, image + at, (size_t)n))) ++randomWrong;
            } else {
                ++randomFail;
                if (expect == ORS_OK) ++randomWrong;
            }
        }
        char uuid[37];
        ors_uuid_string(w->volume_uuid, uuid);
        const int agree = ok == w->present_blocks && dropped == w->dropped_blocks && !damaged && !mismatched && !randomWrong;
        printf("WINDOW %s uuid %s blocks %" PRIu64 " ok %" PRIu64 " dropped %" PRIu64 " damaged %" PRIu64
               " mismatched %" PRIu64 " random ok %" PRIu64 " fail %" PRIu64 " wrong %" PRIu64 " header present %" PRIu64
               " dropped %" PRIu64 " %s\n", w->name, uuid, w->block_count, ok, dropped, damaged, mismatched, randomOk,
               randomFail, randomWrong, w->present_blocks, w->dropped_blocks, agree ? "AGREES" : "DIFFERS");
        failed |= !agree;
        totalOk += ok, totalDropped += dropped, totalDamaged += damaged;
        free(state);
    }
    ors_phys_release(&phys);
    if (fake.live || fake.refused || phys.map_failures) failed = 1;
    printf("MAPS %" PRIu64 " unmaps %" PRIu64 " failures %" PRIu64 " refused %" PRIu64 " left %" PRIu64 "\n", phys.maps,
           phys.unmaps, phys.map_failures, fake.refused, fake.live);
    printf("TOTAL ok %" PRIu64 " dropped %" PRIu64 " damaged %" PRIu64 " reads %" PRIu64 " decodes %" PRIu64 " hits %" PRIu64
           " verified %" PRIu64 " %s\n", totalOk, totalDropped, totalDamaged, reader.stats.reads, reader.stats.decodes,
           reader.stats.hits, reader.stats.verified, failed ? "FAIL" : "PASS");
    free(big);
    free(memory);
    free(slot);
    free(scratch);
    fflush(stdout);
    return failed;
}
