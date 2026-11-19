// SPDX-License-Identifier: BSD-2-Clause-Patent
// OPOIOS (xueying): Goodix Berlin SPI touch protocol (GT9966). See GoodixBerlin.h for the sources and the write rule.
#include "GoodixBerlin.h"
#include <string.h>

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

int gb_checksum_ok(const uint8_t *p, size_t len)
{
    if (!p || len < 2) return 0;
    uint32_t sum = 0;
    for (size_t i = 0; i < len - 2; ++i) sum += p[i];
    return (uint16_t)sum == le16(p + len - 2);
}

int gb_clear_allowed(uint32_t addr) { return addr >= GB_CLEAR_LOW && addr < GB_CLEAR_HIGH; }

static int fail(struct gb *g, const char *stage, int code, int32_t detail)
{
    g->stage = stage;
    g->detail = detail;
    return code;
}

// data NULL: the bytes stay in g->rx after the prefix, until the next transfer.
static int gb_read(struct gb *g, uint32_t addr, uint8_t *data, size_t len)
{
    if (!g->tx || !g->rx || !len || len > GB_XFER_MAX - GB_READ_PREFIX) return GB_E_BUS;
    memset(g->tx, 0xff, GB_READ_PREFIX + len);
    g->tx[0] = GB_READ_FLAG;
    g->tx[1] = (uint8_t)(addr >> 24);
    g->tx[2] = (uint8_t)(addr >> 16);
    g->tx[3] = (uint8_t)(addr >> 8);
    g->tx[4] = (uint8_t)addr;
    ++g->reads;
    if (g->bus.xfer(g->bus.context, g->tx, g->rx, GB_READ_PREFIX + len)) return GB_E_BUS;
    if (data) memcpy(data, g->rx + GB_READ_PREFIX, len);
    return 0;
}

// The one write: a single 0 to the first byte of the touch data buffer. Any other address is refused here, whatever the caller.
static int gb_clear(struct gb *g)
{
    if (!gb_clear_allowed(g->touch_addr)) {
        ++g->refused;
        return GB_E_INFO_ADDR;
    }
    g->tx[0] = GB_WRITE_FLAG;
    g->tx[1] = (uint8_t)(g->touch_addr >> 24);
    g->tx[2] = (uint8_t)(g->touch_addr >> 16);
    g->tx[3] = (uint8_t)(g->touch_addr >> 8);
    g->tx[4] = (uint8_t)g->touch_addr;
    g->tx[5] = 0;
    ++g->writes;
    return g->bus.xfer(g->bus.context, g->tx, g->rx, GB_WRITE_PREFIX + 1) ? GB_E_BUS : 0;
}

static int all_same(const uint8_t *p, size_t len, uint8_t v)
{
    for (size_t i = 0; i < len; ++i) if (p[i] != v) return 0;
    return 1;
}

static int read_version(struct gb *g)
{
    uint8_t v[GB_FW_VERSION_LEN] = {0};
    int rc = 0;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        if (attempt) g->bus.sleep_ms(g->bus.context, 10);
        if ((rc = gb_read(g, GB_FW_VERSION_ADDR, v, sizeof v))) continue;
        if (all_same(v, sizeof v, 0x00) || all_same(v, sizeof v, 0xff)) { rc = GB_E_FW_NONE; continue; }
        if (!gb_checksum_ok(v, sizeof v)) { rc = GB_E_FW_CHECKSUM; continue; }
        // Product ids are ASCII; anything else shows as '?' and a NUL ends the id early.
        for (unsigned i = 0; i < 6; ++i) g->rom_pid[i] = (v[i] >= 0x20 && v[i] <= 0x7e) || !v[i] ? (char)v[i] : '?';
        g->rom_pid[6] = 0;
        for (unsigned i = 0; i < 8; ++i) g->patch_pid[i] = (v[10 + i] >= 0x20 && v[10 + i] <= 0x7e) || !v[10 + i] ? (char)v[10 + i] : '?';
        g->patch_pid[8] = 0;
        memcpy(g->patch_vid, v + 18, 4);
        g->sensor_id = v[23];
        return 0;
    }
    return fail(g, "version", rc, (int32_t)((uint32_t)v[0] | (uint32_t)v[1] << 8 | (uint32_t)v[26] << 16 | (uint32_t)v[27] << 24));
}

int gb_parse_ic_info(struct gb *g, const uint8_t *b, size_t len)
{
    // length (2), version (16): customer, version, die, IC version, config id LE32, config version, 4 data ids, 3 reserved;
    // feature (10); drive, sense, button and force counts; five lists of a count byte and that many LE16 values; then misc.
    if (len < 34 + 2) return GB_E_INFO_SHORT;
    g->config_id = le32(b + 6);
    g->config_version = b[10];
    g->drv_num = b[28];
    g->sen_num = b[29];
    size_t at = 32;
    for (unsigned list = 0; list < 5; ++list) {
        if (at >= len - 2) return GB_E_INFO_SHORT;
        at += 1 + 2u * b[at];
    }
    // misc: cmd addr LE32 @0, cmd max len @4, reply addr @6, reply len @10, fw state addr @12, len @16, fw buffer addr @18,
    // len @22, frame data addr @24, frame head len @28, fw attr len @30, fw log len @32, pack max @34, compress @35, stylus,
    // mutual, self and noise struct lengths @36..42, touch data addr LE32 @44, touch data head len @48, point struct len @50.
    if (at + 52 > len - 2) return GB_E_INFO_SHORT;
    g->touch_addr = le32(b + at + 44);
    g->touch_head_len = le16(b + at + 48);
    g->point_len = le16(b + at + 50);
    if (!gb_clear_allowed(g->touch_addr)) return GB_E_INFO_ADDR;
    if ((g->touch_head_len && g->touch_head_len != GB_HEADER_LEN) || (g->point_len && g->point_len != GB_POINT_LEN))
        return GB_E_INFO_LAYOUT;
    return 0;
}

static int read_ic_info(struct gb *g)
{
    // The block is checked and parsed where the transfer left it (g->rx), before the next transfer: no 1 KiB copy in the kernel.
    const uint8_t *info = g->rx + GB_READ_PREFIX;
    int rc = 0;
    uint16_t length = 0;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        if (attempt) g->bus.sleep_ms(g->bus.context, 10);
        uint8_t l[2];
        if ((rc = gb_read(g, GB_IC_INFO_ADDR, l, 2))) continue;
        length = le16(l);
        if (length < 36 || length >= GB_IC_INFO_MAX) { rc = GB_E_INFO_LENGTH; continue; }
        if ((rc = gb_read(g, GB_IC_INFO_ADDR, NULL, length))) continue;
        if (all_same(info, length, 0x00) || all_same(info, length, 0xff)) { rc = GB_E_INFO_NONE; continue; }
        if (!gb_checksum_ok(info, length)) { rc = GB_E_INFO_CHECKSUM; continue; }
        g->info_len = length;
        if ((rc = gb_parse_ic_info(g, info, length))) return fail(g, "ic info parse", rc, (int32_t)g->touch_addr);
        return 0;
    }
    return fail(g, "ic info", rc, length);
}

int gb_start(struct gb *g)
{
    g->stage = 0;
    g->detail = 0;
    g->touch_addr = 0;
    int rc = read_version(g);
    if (!rc) rc = read_ic_info(g);
    if (rc) g->touch_addr = 0;   // never clear on a controller that did not identify
    return rc;
}

unsigned gb_decode(const uint8_t *p, unsigned count, struct gb_frame *f)
{
    memset(f, 0, sizeof *f);
    for (unsigned i = 0; i < count && i < GB_CONTACTS; ++i, p += GB_POINT_LEN) {
        const unsigned type = p[0] & 0x0f, id = p[0] >> 4;
        if (type == GB_POINT_STYLUS || type == GB_POINT_STYLUS_HOVER || id >= GB_CONTACTS) continue;
        struct gb_contact *c = &f->contact[id];
        if (c->active) continue;   // a repeated id keeps its first point
        c->x = le16(p + 2);
        c->y = le16(p + 4);
        c->width = p[6] > p[7] ? p[6] : p[7];
        c->active = 1;
        ++f->count;
    }
    return f->count;
}

int gb_poll(struct gb *g, struct gb_frame *f)
{
    uint8_t e[GB_EVENT_MAX];
    if (!g->touch_addr) return GB_E_NOT_STARTED;
    int rc = gb_read(g, g->touch_addr, e, GB_FIRST_READ);
    if (rc) return rc;
    g->status = e[0];
    if (!e[0]) return 0;                                       // nothing pending: no clear (both drivers)
    if (!gb_checksum_ok(e, GB_HEADER_LEN)) { gb_clear(g); return GB_E_HEADER; }
    if (e[0] & GB_EVENT_TOUCH) {
        const unsigned count = e[2] & 0x0f;
        if (count > GB_CONTACTS) { gb_clear(g); return GB_E_COUNT; }
        if (count > 2 && (rc = gb_read(g, g->touch_addr + GB_FIRST_READ, e + GB_FIRST_READ, (count - 2) * GB_POINT_LEN)))
            return rc;
        if (count && !gb_checksum_ok(e + GB_HEADER_LEN, count * GB_POINT_LEN + 2)) { gb_clear(g); return GB_E_POINTS; }
        gb_decode(e + GB_HEADER_LEN, count, f);
        rc = gb_clear(g);
        return rc ? rc : 1;
    }
    if (e[0] & GB_EVENT_REQUEST) {
        g->request = e[2];
        rc = gb_clear(g);
        if (rc) return rc;
        return e[2] == GB_REQUEST_RESET ? 2 : 0;               // a config request is not answered: no config is ever sent
    }
    rc = gb_clear(g);                                          // gesture, idle and status events: nothing to report
    return rc ? rc : 0;
}
