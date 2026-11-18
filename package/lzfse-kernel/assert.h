/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* OPOIOS: the kernel has no <assert.h> for C; the vendored LZFSE decoder is built with NDEBUG, so assert is a no-op. */
#ifndef OPOIOS_LZFSE_KERNEL_ASSERT_H
#define OPOIOS_LZFSE_KERNEL_ASSERT_H
#define assert(e) ((void)0)
#endif
