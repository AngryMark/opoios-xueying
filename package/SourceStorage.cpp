// SPDX-License-Identifier: BSD-2-Clause-Patent
// Start the source-built UFS adapter after the original storage family loads.
#include <IOKit/IOService.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/storage/IOBlockStorageDevice.h>
#include <libkern/OSKextLib.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>
#include <IOKit/IOLib.h>
#include <kern/thread.h>

extern kmod_info_t g_kernel_kmod_info;
extern "C" void source_storage_base_init(void) __asm__("__GLOBAL__sub_I_IOBlockStorageDevice.cpp");
extern "C" void source_storage_ufs_init(void) __asm__("__GLOBAL__sub_I_NativeUfs.cpp");
extern "C" void source_storage_ram_init(void) __asm__("__GLOBAL__sub_I_NativeRamBlock.cpp");
extern "C" IOService *native_ufs_source_create(void);
extern "C" bool native_source_root_policies_load(void);
// NativeUfs records how far root start got and the last soft-failure reason.
extern "C" volatile uint32_t native_ufs_root_step;
extern "C" const char *volatile native_ufs_root_failure;

// NativeUfs polls the optional board diagnostic during window reads. The
// minimal kernel does not include it; a weak definition keeps the archive
// linkable and is replaced when the diagnostic component is built in.
extern "C" __attribute__((weak)) void boot_progress_poll(void) {}
// Starts the sheng-log writer (BootLog.c); the board page calls it when that page is built in.
extern "C" void boot_log_tick(unsigned now);
extern "C" volatile uint32_t boot_log_state, boot_log_rounds, boot_log_errors;
extern "C" const char *volatile boot_log_open_refusal;

// Without the board page nothing shows the writer's state, so a log that cannot be written stops the boot
// with the reason on the panic screen instead of leaving an unattended run without a log.
// Once it writes, a writer whose rounds stop for 20 s (a hang elsewhere that blocks it) also panics: the panic screen's log flush then
// keeps the message buffer up to the hang.
static void boot_log_check(void *, wait_result_t)
{
    unsigned waited = 0;
    for (; waited < 30 && !boot_log_rounds; ++waited) {
        if (boot_log_state == 3) break;
        IOSleep(1000);
    }
    if (!boot_log_rounds)
        panic("SourceStorage: sheng-log has no log (state %u, rounds %u, errors %u, open: %s)", boot_log_state,
              boot_log_rounds, boot_log_errors, boot_log_open_refusal ? boot_log_open_refusal : "no refusal");
    uint32_t last = boot_log_rounds;
    for (unsigned still = 0; boot_log_state == 2; IOSleep(1000)) {
        const uint32_t now = boot_log_rounds;
        still = now == last ? still + 1 : 0;
        last = now;
        if (still >= 20)
            panic("SourceStorage: sheng-log writer stalled for 20 s after %u rounds (errors %u)", now, boot_log_errors);
    }
}

static const OSMetaClass *storageParent;
static IOService *storageDriver;
static bool attempted;

// Used only by the deferred source IOBlockStorageDevice metaclass constructor.
// The C++ class name stays unchanged for compiler-authored arm64e discriminators.
extern "C" const OSMetaClass *native_source_storage_parent(void)
{
    if (!storageParent) panic("SourceStorage: metaclass initialized before original family");
    return storageParent;
}

// The Data seed the loader placed in /chosen/memory-map. Its disk starts after UFS, whose store window
// keeps the changed pages of the seed when the board enables persistence.
static void start_data_disk(IOService *provider)
{
    IORegistryEntry *map = IORegistryEntry::fromPath("/chosen/memory-map", gIODTPlane);
    const bool seed = map && (map->getProperty("PackedRAMDisk") || map->getProperty("RAMDisk"));
    OSSafeReleaseNULL(map);
    if (!seed) return;
    IOService *disk = OSDynamicCast(IOService, OSMetaClass::allocClassWithName("NativeRamBlock"));
    if (!disk) panic("SourceStorage: cannot allocate the Data disk");
    const char *step = !disk->init() ? "init" : !disk->attach(provider) ? "attach" : !disk->start(provider) ? "start" : nullptr;
    if (step) panic("SourceStorage: Data disk %s failed", step);
    printf("SourceStorage: Data disk started\n");
}

// OPOIOS: how far the system got, as one row, for a phone without a serial console or storage for logs.
// opoios-sys-report=<seconds> (15 to 3600) starts a kernel thread with the RAM root: every 15 s it prints the row on the
// console, and when the time is up it panics with it, so the panic screen shows the root, the RAM disk traffic and the
// processes by pid (as OddlyLabs/unixnu-fuxi's SYS row). It only reads kernel state. The process ABI is declared here
// with opaque types, as BootProcessProbe.c does, to keep the BSD headers out of this IOKit translation unit.
extern "C" {
struct proc;
struct vnode;
struct mount;
struct proc *proc_find(int);
int proc_rele(struct proc *);
struct vnode *vfs_rootvnode(void);
struct mount *vnode_mount(struct vnode *);
void vfs_name(struct mount *, char *);
int vnode_put(struct vnode *);
extern dev_t rootdev;
extern volatile uint64_t native_ram_block_reads, native_ram_block_writes, native_ram_block_failures;
// BootProcessProbe.c (built into this kernel for iOS 27): its capture walks the processes it knows (launchd first) and
// samples each one's first thread: state flags/priority, wait event (W), continuation (C), user PC (U), shared region
// slide. The capture may wait in proc_iterate, so it runs in its own worker; the report takes the published copy.
void boot_process_capture(void);
void boot_process_snapshot(void);
extern char boot_process_rows[10][120];
// The same capture's OPOIOS row for a waiting launchd: system call (x16, x0) and kernel return addresses (low 36 bits).
extern char opoios_launchd_trace[200];
// launchd (pid 1), BootProcessProbe.c: through proc_find (may wait, for the sampler worker) and through the task first seen
// for it (try-locks only, for the report thread).
void opoios_launchd_sample(void);
extern char opoios_launchd_direct[150];
void opoios_launchd_cached(char *out, size_t size, char *trace, size_t tsize);
void clock_get_uptime(uint64_t *result);
void absolutetime_to_nanoseconds(uint64_t abstime, uint64_t *result);
// Image4MonitorAbsent.c: calls of Image4::start's per-slot TXM call (it reaches them only in its slot loop).
extern volatile uint32_t opoios_image4_monitor_calls;
// BootProcessProbe.c: the kernel thread waiting inside Image4's code, with its frames (try-locks only).
void opoios_image4_thread(char *out, size_t size);
boolean_t ml_validate_nofault(vm_offset_t virtsrc, vm_size_t size);
}

// OPOIOS: AppleImage4's userspace cork and Image4's start (stage 3, device 2026-11-15). launchd waits in AppleImage4's sysctl
// "ignition_blob" (handler 0xfffffff008fdf00c), which polls bit 0 of the byte at +16 of the object its getter
// 0xfffffff008fe2f1c ("get userspace cork") reads from 0xfffffff008071b40 (del2 state +128). The export 0xfffffff008fe301c,
// called only by Image4::start, sets that byte through the same pointer. 0xfffffff008071b00 (state +64) is another object of
// that state, kept in the row for comparison. Image4's __DATA
// keeps the magazine slot count (0xfffffff00b97fc40) and a byte it sets after the slot loop and the uncork call
// (0xfffffff00b97fc48). Static addresses of the 24A446 collection, which the fileset keeps in this kernel, plus the kernel
// slide; every read is checked with ml_validate_nofault, and the row only reads, without locks (the report thread uses it).
static bool opoios_peek(uint64_t address, void *out, size_t size)
{
    if (address < 0xfffffff000000000ULL || !ml_validate_nofault((vm_offset_t)address, (vm_size_t)size)) return false;
    __builtin_memcpy(out, (const void *)address, size);
    return true;
}

static int opoios_cork(char *out, size_t size, uint64_t slot)
{
    uint64_t object = 0;
    uint8_t flag = 0;
    if (!opoios_peek(slot + vm_kernel_slide, &object, sizeof object)) return snprintf(out, size, " ?");
    if (!object) return snprintf(out, size, " 0");
    if (!opoios_peek(object + 16, &flag, sizeof flag)) return snprintf(out, size, " %llx:?", (unsigned long long)object);
    return snprintf(out, size, " %llx:%x", (unsigned long long)object, flag);
}

static void opoios_image4_row(char *out, size_t size)
{
    uint64_t slots = 0;
    uint8_t done = 0xff;
    const bool haveSlots = opoios_peek(0xfffffff00b97fc40ULL + vm_kernel_slide, &slots, sizeof slots);
    const bool haveDone = opoios_peek(0xfffffff00b97fc48ULL + vm_kernel_slide, &done, sizeof done);
    int n = snprintf(out, size, "OPOIOS I4 mon %u slots %lld done %d cork", (unsigned)opoios_image4_monitor_calls,
                     haveSlots ? (long long)slots : -1LL, haveDone ? (int)done : -1);
    if (n > 0 && (size_t)n + 24 < size) n += opoios_cork(out + n, size - (size_t)n, 0xfffffff008071b40ULL);
    if (n > 0 && (size_t)n + 32 < size) n += snprintf(out + n, size - (size_t)n, " s64");
    if (n > 0 && (size_t)n + 24 < size) opoios_cork(out + n, size - (size_t)n, 0xfffffff008071b00ULL);
}

static uint64_t opoios_uptime_seconds(void)
{
    uint64_t now = 0, ns = 0;
    clock_get_uptime(&now);
    absolutetime_to_nanoseconds(now, &ns);
    return ns / 1000000000ULL;
}

static void opoios_process_worker(void *, wait_result_t)
{
    for (;;) {
        boot_process_capture();
        IOSleep(3000);
    }
}

static void opoios_sys_row(char *out, size_t size, unsigned seconds)
{
    char fs[16] = "none";
    struct vnode *root = vfs_rootvnode();
    if (root) {
        vfs_name(vnode_mount(root), fs);
        vnode_put(root);
    }
    int n = snprintf(out, size, "OPOIOS SYS %us root %s %u,%u ram r%llu w%llu f%llu |", seconds, fs,
                     (unsigned)((rootdev >> 24) & 0xff), (unsigned)(rootdev & 0xffffff),
                     (unsigned long long)native_ram_block_reads, (unsigned long long)native_ram_block_writes,
                     (unsigned long long)native_ram_block_failures);
    unsigned found = 0;
    for (int pid = 0; pid < 4000; ++pid) {
        struct proc *p = proc_find(pid);
        if (!p) continue;
        ++found;
        if (found <= 16 && n > 0 && (size_t)n + 40 < size) {
            const char *name = proc_best_name(p);
            n += snprintf(out + n, size - (size_t)n, " %d:%.24s", pid, name ? name : "?");
        }
        proc_rele(p);
    }
    if (n > 0 && (size_t)n + 12 < size) n += snprintf(out + n, size - (size_t)n, " | n%u", found);
    // launchd's first thread (W and C are kernel addresses: symbolize with the kernel's symbol table, slide shown).
    boot_process_snapshot();
    if (n > 0 && (size_t)n + 40 < size)
        n += snprintf(out + n, size - (size_t)n, " | ks%lx %.110s", (unsigned long)vm_kernel_slide, boot_process_rows[0]);
    if (n > 0 && (size_t)n + 40 < size && opoios_launchd_trace[0])
        snprintf(out + n, size - (size_t)n, " | %.190s", opoios_launchd_trace);
}

// OPOIOS: the report thread must keep printing whatever blocks elsewhere. On the device (2026-11-15 20:44) a report that
// sampled pid 1 through proc_find(1) first printed nothing for 11 minutes: proc_find waits while a process is in exec. So
// the samples that take process references (pid 1, then the process list) run in this worker every 3 s and publish their
// last result with its uptime; the report prints that copy with its age and the step the worker is in (1: pid 1,
// 2: process list, 0: sleeping), and itself reads only lock-free state: the Image4 row and launchd's task first seen.
static char opoios_published_sys[640], opoios_published_pid1[160];
static uint64_t opoios_published_at;
static volatile uint32_t opoios_sampler_step;
static uint32_t opoios_publish_lock;

static void opoios_sampler(void *, wait_result_t)
{
    static char sys[640];
    for (;;) {
        opoios_sampler_step = 1;
        opoios_launchd_sample();
        opoios_sampler_step = 2;
        const uint64_t at = opoios_uptime_seconds();
        opoios_sys_row(sys, sizeof sys, (unsigned)at);
        while (__atomic_exchange_n(&opoios_publish_lock, 1u, __ATOMIC_ACQUIRE)) {}
        snprintf(opoios_published_sys, sizeof opoios_published_sys, "%s", sys);
        snprintf(opoios_published_pid1, sizeof opoios_published_pid1, "%s", opoios_launchd_direct);
        opoios_published_at = at;
        __atomic_store_n(&opoios_publish_lock, 0u, __ATOMIC_RELEASE);
        opoios_sampler_step = 0;
        IOSleep(3000);
    }
}

// OPOIOS: where the report thread is: iterations * 10 + the line it is printing (1 I4, 2 I4T, 3 LD, 4 SAMPLE, 5 SYS, 9 between).
static volatile uint32_t opoios_report_mark;

// OPOIOS: a panic that never finishes (device 2026-11-15 22:07: from about 52 s a panic screen started to draw, its first line
// beginning with "Image4, while the other CPUs kept running; the sampler's 3 s sleep never ended and the report's own final
// panic stopped). XNU's debugger globals, read by address (asm labels, so no header declaration can clash) and only through
// ml_validate_nofault: the CPU in the debugger, the CPUs spinning, debugger acknowledgement timeouts, the panic caller, the
// format string and its first three arguments (Darwin arm64 passes them in 8-byte stack slots), and the panic log's start.
extern "C" {
extern char opoios_k_debugger_cpu[] __asm__("_debugger_cpu");
extern char opoios_k_debug_cpus_spinning[] __asm__("_debug_cpus_spinning");
extern char opoios_k_debug_ack_timeout_count[] __asm__("_debug_ack_timeout_count");
extern char opoios_k_debugger_panic_caller[] __asm__("_debugger_panic_caller");
extern char opoios_k_debugger_panic_str[] __asm__("_debugger_panic_str");
extern char opoios_k_debugger_panic_args[] __asm__("_debugger_panic_args");
extern char opoios_k_debug_buf_base[] __asm__("_debug_buf_base");
}

static void opoios_peek_text(uint64_t address, char *out, size_t size)
{
    out[0] = 0;
    if (!address || size < 2) return;
    size_t take = size - 1;
    while (take && !opoios_peek(address, out, take)) take /= 2;  // a string near the end of a mapping
    out[take] = 0;
    for (size_t i = 0; i < take; ++i) {
        if (!out[i]) break;
        if (out[i] == '\n' || out[i] == '\r' || out[i] == '\t') out[i] = ' ';
        else if ((unsigned char)out[i] < 32 || (unsigned char)out[i] > 126) out[i] = '.';
    }
}

static void opoios_panic_row(char *out, size_t size)
{
    int32_t cpu = -2;
    uint32_t spinning = 0, ackTimeouts = 0;
    uint64_t caller = 0, format = 0, args = 0, base = 0, list = 0, slot[3] = {};
    opoios_peek((uint64_t)opoios_k_debugger_cpu, &cpu, sizeof cpu);
    opoios_peek((uint64_t)opoios_k_debug_cpus_spinning, &spinning, sizeof spinning);
    opoios_peek((uint64_t)opoios_k_debug_ack_timeout_count, &ackTimeouts, sizeof ackTimeouts);
    opoios_peek((uint64_t)opoios_k_debugger_panic_caller, &caller, sizeof caller);
    opoios_peek((uint64_t)opoios_k_debugger_panic_str, &format, sizeof format);
    opoios_peek((uint64_t)opoios_k_debugger_panic_args, &args, sizeof args);
    opoios_peek((uint64_t)opoios_k_debug_buf_base, &base, sizeof base);
    if (!format && !caller) {
        snprintf(out, size, "PANIC none (debugger cpu %d spin %u ackto %u)", cpu, spinning, ackTimeouts);
        return;
    }
    if (args && opoios_peek(args, &list, sizeof list) && list) opoios_peek(list, slot, sizeof slot);
    static char text[112], log[232];
    opoios_peek_text(format, text, sizeof text);
    opoios_peek_text(base, log, sizeof log);
    snprintf(out, size, "PANIC cpu %d spin %u ackto %u caller %llx fmt \"%s\" a %llx %llx %llx | log %s", cpu, spinning, ackTimeouts,
             (unsigned long long)caller, text, (unsigned long long)slot[0], (unsigned long long)slot[1],
             (unsigned long long)slot[2], log);
}

// OPOIOS: the diagnostic rows for AstonBootScreen.cpp, which draws them itself every 3 s: in two device runs (2026-11-15 20:44,
// 21:39) no report row reached the message buffer while the screen's clock ran. Lock-free state only, one caller (the screen
// thread): the Image4 row, the kernel thread inside Image4, launchd through its first task, and the sampler's pid 1 copy with
// its uptime and step, and the report thread's mark.
extern "C" unsigned opoios_screen_text(char *out, unsigned size)
{
    static char image4[200], image4Thread[260], cached[200], trace[200], pid1[160], panicRow[560];
    uint64_t at = 0;
    opoios_panic_row(panicRow, sizeof panicRow);
    opoios_image4_row(image4, sizeof image4);
    opoios_image4_thread(image4Thread, sizeof image4Thread);
    opoios_launchd_cached(cached, sizeof cached, trace, sizeof trace);
    if (!__atomic_exchange_n(&opoios_publish_lock, 1u, __ATOMIC_ACQUIRE)) {
        snprintf(pid1, sizeof pid1, "%s", opoios_published_pid1);
        at = opoios_published_at;
        __atomic_store_n(&opoios_publish_lock, 0u, __ATOMIC_RELEASE);
    }
    const int n = snprintf(out, size, "%s\n%s\nI4T %s\nLD %s%s%s\nSAMPLE now %llus at %llus step %u report %u | %s", panicRow,
                           image4, image4Thread, cached, trace[0] ? " | " : "", trace, (unsigned long long)opoios_uptime_seconds(),
                           (unsigned long long)at, (unsigned)opoios_sampler_step, (unsigned)opoios_report_mark, pid1);
    return n > 0 ? (unsigned)n : 0;
}

static void opoios_sys_report(void *argument, wait_result_t)
{
    const unsigned limit = (unsigned)(uintptr_t)argument;
    static char sys[640], pid1[160], image4[360], cached[200], trace[200], image4Thread[260];
    uint64_t at = 0;
    unsigned iteration = 0;
    for (unsigned elapsed = 0; elapsed < limit;) {
        const unsigned step = limit - elapsed < 15 ? limit - elapsed : 15;
        IOSleep(step * 1000);
        elapsed += step;
        ++iteration;
        opoios_image4_row(image4, sizeof image4);
        opoios_report_mark = iteration * 10 + 1;
        printf("%s\n", image4);
        opoios_image4_thread(image4Thread, sizeof image4Thread);
        opoios_report_mark = iteration * 10 + 2;
        printf("OPOIOS I4T %s\n", image4Thread);
        opoios_launchd_cached(cached, sizeof cached, trace, sizeof trace);
        opoios_report_mark = iteration * 10 + 3;
        printf("OPOIOS LD %s%s%s\n", cached, trace[0] ? " | " : "", trace);
        if (!__atomic_exchange_n(&opoios_publish_lock, 1u, __ATOMIC_ACQUIRE)) {
            snprintf(sys, sizeof sys, "%s", opoios_published_sys);
            snprintf(pid1, sizeof pid1, "%s", opoios_published_pid1);
            at = opoios_published_at;
            __atomic_store_n(&opoios_publish_lock, 0u, __ATOMIC_RELEASE);
        }
        const uint64_t now = opoios_uptime_seconds();
        opoios_report_mark = iteration * 10 + 4;
        printf("OPOIOS SAMPLE now %llus at %llus step %u | %s\n", (unsigned long long)now, (unsigned long long)at,
               (unsigned)opoios_sampler_step, pid1);
        opoios_report_mark = iteration * 10 + 5;
        printf("%s\n", sys);
        opoios_report_mark = iteration * 10 + 9;
    }
    opoios_report_mark = 1000;
    panic("%s\nOPOIOS I4T %s\nOPOIOS LD %s | %s\nOPOIOS SAMPLE at %llus step %u | %s\n%s", image4, image4Thread, cached, trace,
          (unsigned long long)at, (unsigned)opoios_sampler_step, pid1, sys);
}

static void opoios_sys_report_start(void)
{
    unsigned seconds = 0;
    if (!PE_parse_boot_argn("opoios-sys-report", &seconds, sizeof(seconds)) || !seconds) return;
    if (seconds < 15) seconds = 15;
    if (seconds > 3600) seconds = 3600;
    thread_t thread;
    if (kernel_thread_start(opoios_process_worker, nullptr, &thread) == KERN_SUCCESS) thread_deallocate(thread);
    if (kernel_thread_start(opoios_sampler, nullptr, &thread) == KERN_SUCCESS) thread_deallocate(thread);
    if (kernel_thread_start(opoios_sys_report, (void *)(uintptr_t)seconds, &thread) == KERN_SUCCESS) {
        thread_deallocate(thread);
        printf("SourceStorage: OPOIOS system report in %u s\n", seconds);
    }
}

// OPOIOS: the loader's RAM disk as the only storage (stage 3 RAM root, rd=md0-ramblock). With opoios-ram-root=1 and
// the source-storage argument off, only the source IOBlockStorageDevice and NativeRamBlock are registered and the RAM
// disk is started on the platform root. NativeUfs is never registered, created or started, so nothing reaches the
// UFS controller; the root policies (they describe a UFS root) are not loaded and no log writer runs. NativeRamBlock
// opens the UFS store only with sheng-data-persist (storeMode), which this board never passes.
static void opoios_ram_root_start(void)
{
    unsigned enabled = 0;
    if (!PE_parse_boot_argn("opoios-ram-root", &enabled, sizeof(enabled)) || enabled != 1 || attempted)
        return;
    attempted = true;
    OSReturn status = OSKextLoadKextWithIdentifier("com.apple.iokit.IOStorageFamily");
    if (status != kOSReturnSuccess)
        panic("SourceStorage: OPOIOS RAM root: IOStorageFamily load failed %x", status);
    const OSSymbol *name = OSSymbol::withCString("IOBlockStorageDevice");
    storageParent = name ? OSMetaClass::getMetaClassWithName(name) : nullptr;
    if (name) name->release();
    if (!storageParent || storageParent->getClassSize() != sizeof(IOBlockStorageDevice))
        panic("SourceStorage: OPOIOS RAM root: original base layout %u differs from source %lu",
              storageParent ? storageParent->getClassSize() : 0, sizeof(IOBlockStorageDevice));
    status = OSKextLoadKextWithIdentifier("com.apple.filesystems.apfs");
    if (status != kOSReturnSuccess)
        panic("SourceStorage: OPOIOS RAM root: APFS load failed %x", status);
    void *handle = OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if (!handle) panic("SourceStorage: OPOIOS RAM root: cannot begin class registration");
    source_storage_base_init();
    source_storage_ram_init();
    status = OSMetaClass::postModLoad(handle);
    if (status != kOSReturnSuccess)
        panic("SourceStorage: OPOIOS RAM root: class registration failed %x", status);

    OSDictionary *matching = IOService::serviceMatching("IOPlatformExpertDevice");
    IOService *provider = matching ? IOService::waitForMatchingService(matching, 5000000000ULL) : nullptr;
    if (!provider) panic("SourceStorage: OPOIOS RAM root: platform root unavailable");
    IORegistryEntry *map = IORegistryEntry::fromPath("/chosen/memory-map", gIODTPlane);
    const bool seed = map && (map->getProperty("PackedRAMDisk") || map->getProperty("RAMDisk"));
    OSSafeReleaseNULL(map);
    if (!seed) panic("SourceStorage: OPOIOS RAM root: the loader handed over no RAM disk");
    start_data_disk(provider);
    printf("SourceStorage: OPOIOS RAM root started, no UFS\n");
    opoios_sys_report_start();
}

extern "C" void native_source_storage_start(void)
{
    unsigned enabled = 0;
    if (!PE_parse_boot_argn("native-source-storage", &enabled, sizeof(enabled)) || enabled != 1 || attempted) {
        opoios_ram_root_start();
        return;
    }
    attempted = true;
    OSReturn status = OSKextLoadKextWithIdentifier("com.apple.iokit.IOStorageFamily");
    if (status != kOSReturnSuccess)
        panic("SourceStorage: IOStorageFamily load failed %x", status);
    const OSSymbol *name = OSSymbol::withCString("IOBlockStorageDevice");
    storageParent = name ? OSMetaClass::getMetaClassWithName(name) : nullptr;
    if (name) name->release();
    if (!storageParent || storageParent->getClassSize() != sizeof(IOBlockStorageDevice))
        panic("SourceStorage: original base layout %u differs from source %lu",
              storageParent ? storageParent->getClassSize() : 0, sizeof(IOBlockStorageDevice));

    // Authenticate policies before registering hardware-facing classes. The
    // firmware hands off the envelope; the trusted anchor is compiled in.
    if (!native_source_root_policies_load())
        panic("SourceStorage: root policy handoff or authentication failed");
    status = OSKextLoadKextWithIdentifier("com.apple.filesystems.apfs");
    if (status != kOSReturnSuccess)
        panic("SourceStorage: APFS load failed %x", status);
    void *handle = OSMetaClass::preModLoad(g_kernel_kmod_info.name);
    if (!handle) panic("SourceStorage: cannot begin class registration");
    source_storage_base_init();
    source_storage_ufs_init();
    source_storage_ram_init();
    status = OSMetaClass::postModLoad(handle);
    if (status != kOSReturnSuccess)
        panic("SourceStorage: class registration failed %x", status);

    OSDictionary *matching = IOService::serviceMatching("IOPlatformExpertDevice");
    IOService *provider = matching ? IOService::waitForMatchingService(matching, 5000000000ULL) : nullptr;
    if (!provider) panic("SourceStorage: platform root unavailable");
    storageDriver = native_ufs_source_create();
    if (!storageDriver) panic("SourceStorage: cannot allocate UFS service");
    const char *step = !storageDriver->init() ? "init" : !storageDriver->attach(provider) ? "attach" :
                       !storageDriver->start(provider) ? "start" : nullptr;
    if (step)
        panic("SourceStorage: UFS %s failed (root step %u: %s)", step, native_ufs_root_step,
              native_ufs_root_failure ? native_ufs_root_failure : "no reason recorded");
    printf("SourceStorage: UFS started through public IOStorageFamily interface\n");
    start_data_disk(provider);
    // The UFS log area exists from here on; the writer only runs with sheng-log=1.
    boot_log_tick(0);
    unsigned log = 0;
    thread_t check;
    if (PE_parse_boot_argn("sheng-log", &log, sizeof(log)) && log == 1 &&
        kernel_thread_start(boot_log_check, nullptr, &check) == KERN_SUCCESS)
        thread_deallocate(check);
}
