// SPDX-License-Identifier: BSD-2-Clause-Patent
// OPOIOS: the RAM root store's windows (OS, SystemOS) as read-only block devices (stage 4 path 1, step 5).
//
// UEFI leaves the store in reserved RAM above the XNU window and a descriptor at the start of that region (see
// OpoiosRootStore.h). opoios_root_store_start() (SourceStorage.cpp, opoios-ram-root=2) maps the descriptor page, sets up
// ors_phys over the store's extents (pinned read-only copyback views of the header, envelopes and chunk tables, and LRU
// mapping windows of opoios-store-window-mib, 64 MiB, for the chunk data: the kernel did not map the whole store at once,
// run store1), authenticates every window's VerifiedRoot envelope with the key compiled into this kernel
// (verified_root_key, the policy anchor) and starts one OpoiosRootStoreDisk per window under the platform root. The original IOBlockStorageDriver then publishes IOMedia, APFS its container and
// volumes. Every block a disk returns has been checked against its signed hash; a dropped or damaged block fails the
// request with an I/O error. SourceRootBinding.cpp asks opoios_root_store_authenticates() which media a disk vouches for.
//
// The memory is outside XNU's managed range: a physical IOMemoryDescriptor with the copyback cache mode maps it through a
// device pager, and pmap takes the cache attributes of a non-managed page from the mapping. Nothing here writes to it.
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/storage/IOBlockStorageDevice.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <libkern/crypto/sha2.h>
#include <kern/task.h>
#include <pexpert/pexpert.h>

extern "C" {
#include "OpoiosRootStore.h"
extern const struct vr_crypto vr_xnu_crypto;
extern const uint8_t verified_root_key[];

// Lock-free state for SourceStorage.cpp's report rows. stage: 1 descriptor page mapped, 2 descriptor valid, 3 store access
// ready, 4 windows authenticated, 5 reader ready, 6 disks started; the negative of the step that failed. error: the
// ors_status (8 = a mapping failed) or the index of the failing disk. probe: which single mappings the kernel gave, tried
// once and released at once (bit 0 the whole store over both extents, as run store1 failed; bit 1 the first extent
// alone; bit 2 1 GiB; bit 3 64 MiB). maps/map failures: the access layer's mappings so far.
volatile int32_t opoios_store_stage = 0;
volatile int32_t opoios_store_error = 0;
volatile uint64_t opoios_store_bytes = 0;
volatile uint32_t opoios_store_disks = 0;
volatile uint32_t opoios_store_probe = 0;
volatile uint64_t opoios_store_maps = 0, opoios_store_map_failures = 0;
volatile uint64_t opoios_store_requests = 0, opoios_store_request_bytes = 0, opoios_store_failures = 0;
volatile uint64_t opoios_store_decodes = 0, opoios_store_hits = 0, opoios_store_verified = 0;
volatile uint64_t opoios_store_dropped = 0, opoios_store_damaged = 0;

bool opoios_root_store_start(IOService *provider);
int opoios_root_store_authenticates(IOService *provider, const char *uuid, uint8_t *digest);
void opoios_root_store_row(char *out, size_t size);
}

namespace {
constexpr unsigned kBounceBytes = 1u << 20;
constexpr unsigned kDefaultCacheMiB = 32;
constexpr IOOptionBits kPhysicalCopyback = static_cast<IOOptionBits>(kIODirectionIn) |
                                           static_cast<IOOptionBits>(kIOMemoryMapperNone) |
                                           (static_cast<IOOptionBits>(kIOCopybackCache) << kIOMemoryBufferCacheShift);
constexpr IOOptionBits kMapReadOnly = static_cast<IOOptionBits>(kIOMapAnywhere) | static_cast<IOOptionBits>(kIOMapReadOnly) |
                                      static_cast<IOOptionBits>(kIOMapCopybackCache);

constexpr unsigned kDefaultWindowMiB = 64;

struct StoreState {
    IOLock *lock = nullptr;                  // serializes the reader, its cache, the mapping windows and the bounce buffer
    ors_phys phys = {};
    ors_store store = {};
    ors_reader reader = {};
    uint8_t *bounce = nullptr;
    bool ready = false;
};
StoreState gStore;

// The platform mapper of ors_phys: one physical range, read-only, copyback (the memory is outside XNU's managed range, so
// the device pager takes the cache mode from the descriptor). The map keeps its descriptor; the handle is the map.
const uint8_t *mapPhysical(void *, uint64_t phys, uint64_t length, void **handle)
{
    IOMemoryDescriptor *memory = IOMemoryDescriptor::withAddressRange(phys, length, kPhysicalCopyback, TASK_NULL);
    IOMemoryMap *map = memory ? memory->createMappingInTask(kernel_task, 0, kMapReadOnly) : nullptr;
    OSSafeReleaseNULL(memory);
    if (!map || map->getLength() < length) {
        OSSafeReleaseNULL(map);
        __atomic_fetch_add(&opoios_store_map_failures, 1, __ATOMIC_RELAXED);
        return nullptr;
    }
    __atomic_fetch_add(&opoios_store_maps, 1, __ATOMIC_RELAXED);
    *handle = map;
    return reinterpret_cast<const uint8_t *>(map->getVirtualAddress());
}

void unmapPhysical(void *, void *handle)
{
    if (handle) static_cast<IOMemoryMap *>(handle)->release();
}

// One mapping of `count` physical ranges, made and released at once: does the kernel give this size?
bool probeMapping(const IOAddressRange *ranges, uint32_t count)
{
    IOMemoryDescriptor *memory = IOMemoryDescriptor::withAddressRanges(const_cast<IOAddressRange *>(ranges), count,
                                                                       kPhysicalCopyback, TASK_NULL);
    IOMemoryMap *map = memory ? memory->createMappingInTask(kernel_task, 0, kMapReadOnly) : nullptr;
    const bool ok = map != nullptr;
    OSSafeReleaseNULL(map);
    OSSafeReleaseNULL(memory);
    return ok;
}

bool fail(int32_t stage, int32_t error, const char *what)
{
    opoios_store_error = error;
    opoios_store_stage = -stage;
    printf("OPOIOS STORE: %s (step %d, error %d)\n", what, (int)stage, (int)error);
    return false;
}

void publishStats()
{
    const ors_stats &s = gStore.reader.stats;
    opoios_store_decodes = s.decodes;
    opoios_store_hits = s.hits;
    opoios_store_verified = s.verified;
    opoios_store_dropped = s.dropped;
    opoios_store_damaged = s.damaged;
}
}

class OpoiosRootStoreDisk : public IOBlockStorageDevice {
    OSDeclareDefaultStructors(OpoiosRootStoreDisk)
    unsigned window = 0;
    uint64_t sectors = 0;
    bool online = false;
    bool digestReady = false;
    uint8_t digest[SHA384_DIGEST_LENGTH] = {};
public:
    bool start(IOService *provider) override;
    bool authenticates(const char *uuid, uint8_t *digestOut);
    IOReturn doEjectMedia() override { return kIOReturnUnsupported; }
    IOReturn doFormatMedia(UInt64) override { return kIOReturnNotWritable; }
    UInt32 doGetFormatCapacities(UInt64 *, UInt32) const override { return 0; }
    char *getVendorString() override { return const_cast<char *>("OPOIOS"); }
    char *getProductString() override { return const_cast<char *>("RAM root store"); }
    char *getRevisionString() override { return const_cast<char *>("1.0"); }
    char *getAdditionalDeviceInfoString() override { return const_cast<char *>("read-only, every block verified"); }
    IOReturn reportBlockSize(UInt64 *value) override { *value = 512; return kIOReturnSuccess; }
    IOReturn reportEjectability(bool *value) override { *value = false; return kIOReturnSuccess; }
    IOReturn reportMaxValidBlock(UInt64 *value) override { *value = sectors - 1; return kIOReturnSuccess; }
    IOReturn reportMediaState(bool *present, bool *changed) override
    {
        *present = online;
        if (changed) *changed = false;
        return kIOReturnSuccess;
    }
    IOReturn reportRemovability(bool *value) override { *value = false; return kIOReturnSuccess; }
    IOReturn reportWriteProtection(bool *value) override { *value = true; return kIOReturnSuccess; }
    IOReturn doSynchronize(UInt64, UInt64, IOOptionBits) override { return online ? kIOReturnSuccess : kIOReturnNotReady; }
    IOReturn getWriteCacheState(bool *value) override { *value = false; return kIOReturnSuccess; }
    IOReturn setWriteCacheState(bool) override { return kIOReturnUnsupported; }
    IOReturn doAsyncReadWrite(IOMemoryDescriptor *buffer, UInt64 block, UInt64 count, IOStorageAttributes *,
                              IOStorageCompletion *completion) override;
};
OSDefineMetaClassAndStructors(OpoiosRootStoreDisk, IOBlockStorageDevice)

bool OpoiosRootStoreDisk::start(IOService *provider)
{
    if (!IOBlockStorageDevice::start(provider)) return false;
    OSNumber *index = OSDynamicCast(OSNumber, getProperty("opoios-window"));
    if (!gStore.ready || !index || index->unsigned32BitValue() >= gStore.store.window_count) return false;
    window = index->unsigned32BitValue();
    const ors_window &w = gStore.store.window[window];
    if (w.image_bytes % 512) return false;
    sectors = w.image_bytes / 512;
    char uuid[37];
    ors_uuid_string(w.volume_uuid, uuid);
    setProperty("opoios-window-name", w.name);
    setProperty("opoios-volume-uuid", uuid);
    // As RamBlock 737f6da: the medium is solid state.
    OSDictionary *characteristics = OSDictionary::withCapacity(1);
    OSString *medium = OSString::withCString("Solid State");
    if (characteristics && medium && characteristics->setObject("Medium Type", medium))
        setProperty("Device Characteristics", characteristics);
    OSSafeReleaseNULL(medium);
    OSSafeReleaseNULL(characteristics);
    online = true;
    registerService();
    return true;
}

bool OpoiosRootStoreDisk::authenticates(const char *uuid, uint8_t *digestOut)
{
    if (!online || !uuid) return false;
    const ors_window &w = gStore.store.window[window];
    char expected[37];
    ors_uuid_string(w.volume_uuid, expected);
    if (strcmp(uuid, expected)) return false;
    if (digestOut) {
        // As NativeVirtioBlock and NativeUfs: SHA-384 of the authenticated envelope (header, signature, block hashes).
        IOLockLock(gStore.lock);
        if (!digestReady) {
            SHA384_CTX context;
            SHA384_Init(&context);
            SHA384_Update(&context, w.envelope, static_cast<size_t>(w.envelope_bytes));
            SHA384_Final(digest, &context);
            digestReady = true;
        }
        memcpy(digestOut, digest, sizeof(digest));
        IOLockUnlock(gStore.lock);
    }
    return true;
}

IOReturn OpoiosRootStoreDisk::doAsyncReadWrite(IOMemoryDescriptor *buffer, UInt64 block, UInt64 count, IOStorageAttributes *,
                                               IOStorageCompletion *completion)
{
    if (!buffer || !completion || !completion->action || !count || block >= sectors || count > sectors - block ||
        buffer->getLength() < count * 512) return kIOReturnBadArgument;
    if (buffer->getDirection() != kIODirectionIn) return kIOReturnNotWritable;
    if (!online) return kIOReturnNotReady;
    const uint64_t bytes = count * 512;
    uint64_t done = 0;
    IOReturn result = kIOReturnSuccess;
    IOLockLock(gStore.lock);
    while (done < bytes) {
        const uint64_t piece = bytes - done < kBounceBytes ? bytes - done : kBounceBytes;
        const int status = ors_read(&gStore.reader, &gStore.store, window, block * 512 + done, gStore.bounce, piece,
                                    &vr_xnu_crypto);
        if (status != ORS_OK) {
            result = kIOReturnIOError;
            break;
        }
        if (buffer->writeBytes(done, gStore.bounce, piece) != piece) {
            result = kIOReturnIOError;
            break;
        }
        done += piece;
    }
    publishStats();
    IOLockUnlock(gStore.lock);
    __atomic_fetch_add(&opoios_store_requests, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&opoios_store_request_bytes, done, __ATOMIC_RELAXED);
    if (result) __atomic_fetch_add(&opoios_store_failures, 1, __ATOMIC_RELAXED);
    completion->action(completion->target, completion->parameter, result, done);
    return kIOReturnSuccess;
}

extern "C" int opoios_root_store_authenticates(IOService *provider, const char *uuid, uint8_t *digest)
{
    OpoiosRootStoreDisk *disk = OSDynamicCast(OpoiosRootStoreDisk, provider);
    if (!disk) return -1;
    return disk->authenticates(uuid, digest) ? 1 : 0;
}

extern "C" bool opoios_root_store_start(IOService *provider)
{
    if (gStore.ready || opoios_store_stage) return gStore.ready;
    uint64_t region = ORS_REGION_BASE;
    PE_parse_boot_argn("opoios-store-base", &region, sizeof(region));
    if (region & (ORS_BLOCK - 1)) return fail(1, 0, "region base not page aligned");

    // 1-2. The descriptor page.
    IOMemoryDescriptor *page = IOMemoryDescriptor::withAddressRange(region, ORS_BLOCK, kPhysicalCopyback, TASK_NULL);
    IOMemoryMap *pageMap = page ? page->createMappingInTask(kernel_task, 0, kMapReadOnly) : nullptr;
    if (!pageMap) {
        OSSafeReleaseNULL(page);
        return fail(1, 0, "cannot map the descriptor page");
    }
    opoios_store_stage = 1;
    ors_descriptor d;
    const int parsed = ors_descriptor_parse(reinterpret_cast<const uint8_t *>(pageMap->getVirtualAddress()), ORS_BLOCK,
                                            &vr_xnu_crypto, &d);
    pageMap->release();
    page->release();
    if (parsed) return fail(2, parsed, "no valid store descriptor (no store received?)");
    if (d.extent[0].base < region + ORS_BLOCK) return fail(2, 0, "store overlaps its descriptor");
    opoios_store_bytes = d.store_bytes;
    opoios_store_stage = 2;

    // 3. Access to the store: never one mapping of all of it (run store1: the 7.5 GiB mapping failed), but pinned views of
    // its header, envelopes and tables and mapping windows for the chunk data, each inside one physical extent. First,
    // once, which sizes the kernel maps at all (released at once; only for the report).
    {
        IOAddressRange ranges[2] = {};
        uint32_t count = 0;
        uint64_t left = (d.store_bytes + ORS_BLOCK - 1) & ~static_cast<uint64_t>(ORS_BLOCK - 1);
        for (unsigned i = 0; i < d.extent_count && left; ++i) {
            const uint64_t take = d.extent[i].bytes < left ? d.extent[i].bytes : left;
            ranges[count++] = {d.extent[i].base, take};
            left -= take;
        }
        uint32_t probe = 0;
        if (!left && probeMapping(ranges, count)) probe |= 1;
        if (probeMapping(ranges, 1)) probe |= 2;
        IOAddressRange gib = {d.extent[0].base, d.extent[0].bytes < (1ull << 30) ? d.extent[0].bytes : (1ull << 30)};
        if (probeMapping(&gib, 1)) probe |= 4;
        IOAddressRange window = {d.extent[0].base, d.extent[0].bytes < (64ull << 20) ? d.extent[0].bytes : (64ull << 20)};
        if (probeMapping(&window, 1)) probe |= 8;
        opoios_store_probe = probe;
    }
    unsigned windowMiB = kDefaultWindowMiB;
    PE_parse_boot_argn("opoios-store-window-mib", &windowMiB, sizeof(windowMiB));
    if (windowMiB < 1) windowMiB = 1;
    if (windowMiB > 1024) windowMiB = 1024;
    const int access = ors_phys_init(&gStore.phys, &d, static_cast<uint64_t>(windowMiB) << 20, nullptr, mapPhysical,
                                     unmapPhysical);
    if (access) return fail(3, access, "store layout");
    opoios_store_stage = 3;

    // 4. Every window's envelope against the compiled-in key (ors_open pins what it keeps).
    ors_access storeAccess;
    ors_phys_access(&gStore.phys, &storeAccess);
    const int opened = ors_open(&gStore.store, &storeAccess, d.store_bytes, verified_root_key, &vr_xnu_crypto);
    if (opened) return fail(4, opened, ors_status_name(opened));
    opoios_store_stage = 4;

    // 5. The reader: LZFSE scratch, decoded-chunk cache, bounce buffer.
    unsigned mib = kDefaultCacheMiB;
    PE_parse_boot_argn("opoios-store-cache-mib", &mib, sizeof(mib));
    if (mib < 1) mib = 1;
    if (mib > 256) mib = 256;
    const unsigned slots = mib * (1u << 20) / ORS_CHUNK;
    void *scratch = IOMallocZeroData(ors_scratch_bytes());
    ors_slot *slot = static_cast<ors_slot *>(IOMallocZero(sizeof(ors_slot) * slots));
    uint8_t *memory = static_cast<uint8_t *>(IOMallocData(static_cast<vm_size_t>(slots) * ORS_CHUNK));
    gStore.bounce = static_cast<uint8_t *>(IOMallocData(kBounceBytes));
    gStore.lock = IOLockAlloc();
    if (!scratch || !slot || !memory || !gStore.bounce || !gStore.lock) return fail(5, 0, "out of memory for the reader");
    ors_reader_init(&gStore.reader, scratch, slot, memory, slots);
    gStore.ready = true;
    opoios_store_stage = 5;

    // 6. One disk per window, as SourceStorage starts the Data disk.
    for (unsigned i = 0; i < gStore.store.window_count; ++i) {
        IOService *disk = OSDynamicCast(IOService, OSMetaClass::allocClassWithName("OpoiosRootStoreDisk"));
        OSNumber *index = OSNumber::withNumber(i, 32);
        const bool started = disk && index && disk->init() && disk->setProperty("opoios-window", index) &&
                             disk->attach(provider) && disk->start(provider);
        OSSafeReleaseNULL(index);
        if (!started) {
            OSSafeReleaseNULL(disk);
            return fail(6, static_cast<int32_t>(i), "a window disk did not start");
        }
        disk->release();
        __atomic_fetch_add(&opoios_store_disks, 1, __ATOMIC_RELAXED);
    }
    opoios_store_stage = 6;
    char uuid[37];
    for (unsigned i = 0; i < gStore.store.window_count; ++i) {
        const ors_window &w = gStore.store.window[i];
        ors_uuid_string(w.volume_uuid, uuid);
        printf("OPOIOS STORE: %s %llu bytes, volume %s, %llu blocks kept, %llu dropped\n", w.name,
               (unsigned long long)w.image_bytes, uuid, (unsigned long long)w.present_blocks,
               (unsigned long long)w.dropped_blocks);
    }
    return true;
}

// One row for the SYS report and the panic screen: stage (negative: the step that failed) and error, store size, disks,
// requests/failures, chunk decodes/cache hits, blocks verified, dropped and damaged reads.
extern "C" void opoios_root_store_row(char *out, size_t size)
{
    snprintf(out, size, "STORE st %d err %d bytes %llu probe %x maps %llu/%llu disks %u req %llu/%lluMiB fail %llu dec %llu "
             "hit %llu ver %llu drop %llu dmg %llu", (int)opoios_store_stage, (int)opoios_store_error,
             (unsigned long long)opoios_store_bytes, (unsigned)opoios_store_probe, (unsigned long long)opoios_store_maps,
             (unsigned long long)opoios_store_map_failures, (unsigned)opoios_store_disks,
             (unsigned long long)opoios_store_requests, (unsigned long long)(opoios_store_request_bytes >> 20),
             (unsigned long long)opoios_store_failures, (unsigned long long)opoios_store_decodes,
             (unsigned long long)opoios_store_hits, (unsigned long long)opoios_store_verified,
             (unsigned long long)opoios_store_dropped, (unsigned long long)opoios_store_damaged);
}
