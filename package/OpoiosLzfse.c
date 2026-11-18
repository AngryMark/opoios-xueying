/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* OPOIOS: the vendored reference LZFSE decoder (package/lzfse) behind a buffer entry point for OpoiosRootStore.c.
 * Same as lzfse_decode_buffer_with_scratch (lzfse_decode.c), which is not built because its lzfse_decode_buffer falls
 * back to malloc. Output is bounded by dst_size; a stream that is cut short or malformed returns 0, one that would
 * write more returns dst_size (the caller verifies every block it uses). */
/* Apple's headers as they are: their warnings (sign comparisons and the like) are not this file's. */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#include "lzfse_internal.h"
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

size_t ors_lzfse_scratch_bytes(void);
size_t ors_lzfse_decode(uint8_t *dst, size_t dst_size, const uint8_t *src, size_t src_size, void *scratch);

size_t ors_lzfse_scratch_bytes(void)
{
    return sizeof(lzfse_decoder_state);
}

size_t ors_lzfse_decode(uint8_t *dst, size_t dst_size, const uint8_t *src, size_t src_size, void *scratch)
{
    lzfse_decoder_state *s = (lzfse_decoder_state *)scratch;
    memset(s, 0, sizeof(*s));
    s->src = src;
    s->src_begin = src;
    s->src_end = src + src_size;
    s->dst = dst;
    s->dst_begin = dst;
    s->dst_end = dst + dst_size;
    const int status = lzfse_decode(s);
    if (status == LZFSE_STATUS_DST_FULL) return dst_size;
    if (status != LZFSE_STATUS_OK) return 0;
    return (size_t)(s->dst - dst);
}
