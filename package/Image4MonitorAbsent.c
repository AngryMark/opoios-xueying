/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* OPOIOS: the trusted execution monitor this board does not have. iPhone17,2's kernel hands some Image4 requests to TXM
 * (txm_kernel_call); the native kernel has no TXM and no function of the same body, so XnuPrelink cannot pair them and the
 * fileset routes the original callers to unixnu_fileset_unmapped (panic).
 *
 * Image4::start (com.apple.security.Image4) tells the monitor about every magazine slot with the kernel function at
 * 0xfffffff00b11beac (TXM selector 52, three arguments, an errno result) and ignores the result: it goes on to the next slot,
 * then uncorks AppleImage4's userspace (the flag launchd's sysctl "activate" waits for) and registers the service. With no
 * monitor there is nobody to tell, so this stand-in does nothing and says so with ENOTSUP. It is bound to that one call site
 * (Image4's GOT slot, scripts/fileset-24A446-d94ap-symbols.json "sites"); every other unpaired kernel function stays a panic.
 *
 * The count and the last arguments are kept for diagnostics. */
#include <stdint.h>

#define OPOIOS_ENOTSUP 45

volatile uint32_t opoios_image4_monitor_calls;
volatile uint64_t opoios_image4_monitor_last[3];

int opoios_image4_monitor_absent(uint64_t arg0, uint64_t arg1, uint64_t arg2);
int opoios_image4_monitor_absent(uint64_t arg0, uint64_t arg1, uint64_t arg2)
{
  opoios_image4_monitor_last[0] = arg0;
  opoios_image4_monitor_last[1] = arg1;
  opoios_image4_monitor_last[2] = arg2;
  __atomic_fetch_add (&opoios_image4_monitor_calls, 1, __ATOMIC_RELAXED);
  return OPOIOS_ENOTSUP;
}
