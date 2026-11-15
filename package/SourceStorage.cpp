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

static void opoios_sys_report(void *argument, wait_result_t)
{
    const unsigned limit = (unsigned)(uintptr_t)argument;
    char row[640] = "";
    for (unsigned elapsed = 0; elapsed < limit;) {
        const unsigned step = limit - elapsed < 15 ? limit - elapsed : 15;
        IOSleep(step * 1000);
        elapsed += step;
        opoios_sys_row(row, sizeof row, elapsed);
        printf("%s\n", row);
    }
    panic("%s", row);
}

static void opoios_sys_report_start(void)
{
    unsigned seconds = 0;
    if (!PE_parse_boot_argn("opoios-sys-report", &seconds, sizeof(seconds)) || !seconds) return;
    if (seconds < 15) seconds = 15;
    if (seconds > 3600) seconds = 3600;
    thread_t thread;
    if (kernel_thread_start(opoios_process_worker, nullptr, &thread) == KERN_SUCCESS) thread_deallocate(thread);
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
