// SPDX-License-Identifier: BSD-2-Clause-Patent
// OPOIOS (xueying): the Goodix Berlin SPI touch protocol of the OnePlus Open's GT9966 (inner panel; the outer GT9916 speaks the
// same). Written from the register map and frame formats that two GPL drivers document: Linux drivers/input/touchscreen/
// goodix_berlin_{core,spi}.c and goodix_berlin.h (the "_D" variant: GT9916), and OnePlus' oplus_touchscreen_v2/Goodix/GT9966/
// goodix_brl_core.{c,h} (OnePlusOSS android_kernel_modules_and_devicetree_oneplus_sm8550, oneplus/sm8550_b_16.0.0_oneplus_open).
// No code is taken from them. Portable C: the caller owns the bus, the GPIOs and the timing.
//
// Towards the controller this is read-only except one byte: after each event it writes 0 to the first byte of the touch data
// buffer, as both drivers do, and gb_clear_allowed() confines that write to the controller's register window that holds the
// buffer. Nothing here writes the boot option, a command, the config, the ISP RAM or the flash; nothing is downloaded. The
// firmware and the config stay as OxygenOS left them in the controller's flash.
#ifndef OPOIOS_GOODIX_BERLIN_H
#define OPOIOS_GOODIX_BERLIN_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

// SPI frames: read = 0xF1, 4-byte big-endian address, 3 dummy bytes, then the data; write = 0xF0, address, data. Mode 0, 8 bits.
#define GB_READ_FLAG 0xF1
#define GB_WRITE_FLAG 0xF0
#define GB_READ_PREFIX 8
#define GB_WRITE_PREFIX 5
// Registers (both drivers): firmware version (28 bytes with its checksum) and the IC information block (16-bit length first).
#define GB_FW_VERSION_ADDR 0x10014u
#define GB_FW_VERSION_LEN 28
#define GB_IC_INFO_ADDR 0x10070u
#define GB_IC_INFO_MAX 1024
// The touch data buffer: an 8-byte header (status, -, count, -, -, -, checksum LE16), then 8 bytes per point, then a checksum
// (LE16) over the points. Header byte 0: 0x80 touch event, 0x40 request event (byte 2: 0x03 reset, 0x01 config).
#define GB_HEADER_LEN 8
#define GB_POINT_LEN 8
#define GB_CONTACTS 10
#define GB_EVENT_TOUCH 0x80
#define GB_EVENT_REQUEST 0x40
#define GB_REQUEST_RESET 0x03
// A point: byte 0 = id << 4 | type (1 stylus hover, 3 stylus), x LE16 at 2, y LE16 at 4, widths at 6 and 7.
#define GB_POINT_STYLUS_HOVER 1
#define GB_POINT_STYLUS 3
// First read of an event: header, two points and the checksum that follows them when there are at most two.
#define GB_FIRST_READ (GB_HEADER_LEN + 2 * GB_POINT_LEN + 2)
#define GB_EVENT_MAX (GB_HEADER_LEN + GB_CONTACTS * GB_POINT_LEN + 2)
// Largest transfer: a read of the whole IC information block. The caller's tx and rx buffers hold at least this.
#define GB_XFER_MAX (GB_READ_PREFIX + GB_IC_INFO_MAX)
// The only address range the clear may write: the touch data buffer lives in it (GT9966 register map: 0x1027C pen data,
// 0x102F6 edge data, 0x1036C algorithm sync). The boot option 0x10000, the command register 0x10174, the flash command 0x13400
// and the ISP buffer 0x13410 are outside it.
#define GB_CLEAR_LOW 0x10200u
#define GB_CLEAR_HIGH 0x10400u

struct gb_contact { uint16_t x, y; uint8_t active, width; };
struct gb_frame { struct gb_contact contact[GB_CONTACTS]; unsigned count; };
struct gb_bus {
    void *context;
    // One full-duplex transfer with chip select held throughout: len bytes of tx clocked out while rx is filled. 0 on success.
    int (*xfer)(void *, const uint8_t *tx, uint8_t *rx, size_t len);
    void (*sleep_ms)(void *, unsigned);
};
struct gb {
    struct gb_bus bus;
    uint8_t *tx, *rx;                 // the caller's buffers, GB_XFER_MAX bytes each
    // Firmware version: the ROM and patch product ids (ASCII, NUL-terminated here), the patch version, the sensor id.
    char rom_pid[7], patch_pid[9];
    uint8_t patch_vid[4], sensor_id;
    // IC information.
    uint16_t info_len;
    uint32_t config_id;
    uint8_t config_version, drv_num, sen_num;
    uint32_t touch_addr;
    uint16_t touch_head_len, point_len;
    // Last event and statistics.
    uint8_t status, request;
    uint32_t reads, writes, refused;
    const char *stage;                // the step that failed, for the diagnostic page
    int32_t detail;
};
// Reads and checks the firmware version and the IC information (up to three attempts each, 10 ms apart); no write.
// 0 or a negative code (GB_E_*).
int gb_start(struct gb *);
// One event from the touch data buffer: 1 touch frame (count may be 0: every contact lifted), 2 the controller asks for a reset,
// 0 nothing pending or another event, negative a failure (the buffer is still cleared when its header could be read).
int gb_poll(struct gb *, struct gb_frame *);
// The touch points of an event (count points at p), stylus points and ids out of range dropped. Returns the contacts kept.
unsigned gb_decode(const uint8_t *points, unsigned count, struct gb_frame *);
// 1 when the byte sum (16 bits) of all but the last two bytes equals the little-endian value in the last two.
int gb_checksum_ok(const uint8_t *, size_t);
// Parses an IC information block (length field first, checksum last, both already checked) into g. 0 or GB_E_INFO_*.
int gb_parse_ic_info(struct gb *, const uint8_t *, size_t);
int gb_clear_allowed(uint32_t addr);

#define GB_E_BUS (-201)            // the transfer itself failed
#define GB_E_FW_NONE (-202)        // the version reads as all 0x00 or 0xFF: nothing answers
#define GB_E_FW_CHECKSUM (-203)
#define GB_E_INFO_LENGTH (-211)
#define GB_E_INFO_NONE (-212)
#define GB_E_INFO_CHECKSUM (-213)
#define GB_E_INFO_SHORT (-214)     // the variable lists run past the block
#define GB_E_INFO_ADDR (-215)      // the touch data address is outside the clear window: refused, never written
#define GB_E_INFO_LAYOUT (-216)    // header or point size other than 8
#define GB_E_HEADER (-221)
#define GB_E_POINTS (-222)
#define GB_E_COUNT (-223)
#define GB_E_NOT_STARTED (-224)

#ifdef __cplusplus
}
#endif
#endif
