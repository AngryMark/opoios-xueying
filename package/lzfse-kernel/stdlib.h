/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* OPOIOS: lzfse_fse.h includes <stdlib.h> but the decoder uses nothing from it (malloc is only in lzfse_decode.c, which the
 * kernel does not build). */
#ifndef OPOIOS_LZFSE_KERNEL_STDLIB_H
#define OPOIOS_LZFSE_KERNEL_STDLIB_H
#include <stddef.h>
#endif
