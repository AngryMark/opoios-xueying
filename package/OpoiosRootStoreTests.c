/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* Host check of OpoiosRootStore.c with VerifiedRoot's OpenSSL provider (built by scripts/check-opoios-root-store.py).
 *
 *   ors-test check STORE KEY [--slots N] [--random N] [--image NAME=PATH]...
 *       open the store with the trusted anchor KEY (395 bytes); read every 4 KiB block of every window through ors_read
 *       (ok, dropped or damaged; ok blocks equal to the image when one is given); then N random reads of 512-byte
 *       aligned ranges up to 256 KiB, each of which must succeed exactly when every block it touches did.
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
    const char *imageName[ORS_MAX_WINDOWS] = {0}, *imagePath[ORS_MAX_WINDOWS] = {0};
    unsigned images = 0;
    for (int i = 4; i < argc; ++i) {
        if (!strcmp(argv[i], "--slots") && i + 1 < argc) slots = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--random") && i + 1 < argc) randoms = (unsigned)strtoul(argv[++i], NULL, 0);
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
    struct ors_store store;
    int status = ors_open(&store, base, storeBytes, key, &provider);
    if (status) {
        printf("OPEN %s\n", ors_status_name(status));
        return 1;
    }
    printf("OPEN ok %u windows\n", store.window_count);
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
