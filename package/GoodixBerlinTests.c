// SPDX-License-Identifier: BSD-2-Clause-Patent
// Host test of GoodixBerlin.c against a model controller: the model answers 0xF1 reads from a register map and records every
// 0xF0 write. Checks identification, event decoding, checksum and count failures, the reset request, and that the only write
// the core ever issues is one 0 byte at the touch data address. Nothing here touches hardware.
#include "GoodixBerlin.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); exit(1); } } while (0)

static uint8_t mem[0x10000];                 // registers 0x10000..0x1ffff
struct wr { uint32_t addr; size_t len; uint8_t first; };
static struct wr writes[256];
static unsigned nwrites, nreads, failNext;
static int xfer(void *ctx, const uint8_t *tx, uint8_t *rx, size_t len)
{
    (void)ctx;
    if (failNext) { --failNext; return -5; }
    if (len < 5) return -22;
    const uint32_t addr = (uint32_t)tx[1] << 24 | (uint32_t)tx[2] << 16 | (uint32_t)tx[3] << 8 | tx[4];
    if (tx[0] == GB_READ_FLAG) {
        CHECK(len >= GB_READ_PREFIX && tx[5] == 0xff && tx[6] == 0xff && tx[7] == 0xff);
        ++nreads;
        memset(rx, 0x5a, GB_READ_PREFIX);
        for (size_t i = 0; i < len - GB_READ_PREFIX; ++i) {
            const uint32_t a = addr + (uint32_t)i;
            rx[GB_READ_PREFIX + i] = (a >= 0x10000 && a < 0x20000) ? mem[a - 0x10000] : 0xff;
        }
        return 0;
    }
    if (tx[0] == GB_WRITE_FLAG) {
        CHECK(nwrites < 256);
        writes[nwrites++] = (struct wr){addr, len - GB_WRITE_PREFIX, tx[5]};
        for (size_t i = 0; i < len - GB_WRITE_PREFIX; ++i) mem[addr - 0x10000 + i] = tx[GB_WRITE_PREFIX + i];
        return 0;
    }
    return -22;
}
static void sleep_ms(void *ctx, unsigned ms) { (void)ctx; (void)ms; }

static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (8 * i)); }
static void seal(uint8_t *p, size_t len)   // checksum of all but the last two bytes into the last two
{
    unsigned sum = 0;
    for (size_t i = 0; i < len - 2; ++i) sum += p[i];
    put16(p + len - 2, sum & 0xffff);
}
static uint8_t *reg(uint32_t a) { return mem + (a - 0x10000); }

static void model_version(void)
{
    uint8_t *v = reg(GB_FW_VERSION_ADDR);
    memset(v, 0, GB_FW_VERSION_LEN);
    memcpy(v, "BERLIN", 6);
    memcpy(v + 10, "9966", 4);
    v[18] = 0x01; v[19] = 0x02; v[20] = 0x03; v[21] = 0x04;
    v[23] = 3;
    seal(v, GB_FW_VERSION_LEN);
}
// An IC information block with list counts lists[5] and the given touch data address and sizes; returns its length.
static unsigned model_info(const unsigned lists[5], uint32_t touch, unsigned head, unsigned point)
{
    uint8_t b[GB_IC_INFO_MAX];
    memset(b, 0, sizeof b);
    put32(b + 6, 0x12345678);
    b[10] = 7;
    b[28] = 36; b[29] = 38;
    unsigned at = 32;
    for (unsigned l = 0; l < 5; ++l) { b[at] = (uint8_t)lists[l]; for (unsigned k = 0; k < lists[l]; ++k) put16(b + at + 1 + 2 * k, 100 + k); at += 1 + 2 * lists[l]; }
    put32(b + at + 0, 0x10174);                 // cmd addr
    put32(b + at + 44, touch);
    put16(b + at + 48, head);
    put16(b + at + 50, point);
    const unsigned len = at + 60 + 2;
    put16(b, len);
    seal(b, len);
    memcpy(reg(GB_IC_INFO_ADDR), b, len);
    return len;
}
static void model_event(uint32_t touch, uint8_t status, uint8_t byte2, const uint8_t (*points)[8], unsigned n)
{
    uint8_t e[GB_EVENT_MAX];
    memset(e, 0, sizeof e);
    e[0] = status; e[2] = byte2;
    seal(e, GB_HEADER_LEN);
    for (unsigned i = 0; i < n; ++i) memcpy(e + GB_HEADER_LEN + 8 * i, points[i], 8);
    if (n) seal(e + GB_HEADER_LEN, 8 * n + 2);
    memcpy(reg(touch), e, sizeof e);
}
static void point(uint8_t p[8], unsigned id, unsigned type, unsigned x, unsigned y, unsigned w)
{
    p[0] = (uint8_t)(id << 4 | type); p[1] = 0; put16(p + 2, x); put16(p + 4, y); p[6] = (uint8_t)w; p[7] = (uint8_t)(w / 2);
}

static uint8_t txb[GB_XFER_MAX], rxb[GB_XFER_MAX];
static struct gb fresh(void)
{
    struct gb g;
    memset(&g, 0, sizeof g);
    g.bus = (struct gb_bus){NULL, xfer, sleep_ms};
    g.tx = txb; g.rx = rxb;
    return g;
}
static void writes_only_clears(uint32_t touch)
{
    for (unsigned i = 0; i < nwrites; ++i) CHECK(writes[i].addr == touch && writes[i].len == 1 && writes[i].first == 0);
}

int main(void)
{
    const uint32_t T = 0x10308;
    const unsigned lists[5] = {3, 5, 2, 2, 4};
    // Checksums and the clear window.
    { uint8_t p[6] = {1, 2, 3, 4, 10, 0}; CHECK(gb_checksum_ok(p, 6)); p[4] = 11; CHECK(!gb_checksum_ok(p, 6)); CHECK(!gb_checksum_ok(p, 1)); }
    CHECK(gb_clear_allowed(0x10308) && gb_clear_allowed(0x10200) && !gb_clear_allowed(0x10400) && !gb_clear_allowed(0x10000));
    CHECK(!gb_clear_allowed(0x10174) && !gb_clear_allowed(0x13400) && !gb_clear_allowed(0x13410) && !gb_clear_allowed(0x40000));

    // Nothing answers (all 0xFF): no identification, no write.
    memset(mem, 0xff, sizeof mem);
    struct gb g = fresh();
    CHECK(gb_start(&g) == GB_E_FW_NONE && g.touch_addr == 0 && nwrites == 0);
    struct gb_frame f;
    CHECK(gb_poll(&g, &f) == GB_E_NOT_STARTED && nwrites == 0);
    // Bad version checksum on every attempt.
    memset(mem, 0, sizeof mem);
    model_version();
    reg(GB_FW_VERSION_ADDR)[27] ^= 1;
    g = fresh();
    CHECK(gb_start(&g) == GB_E_FW_CHECKSUM && nwrites == 0);
    model_version();
    // Bus failure on the first attempt only: the retry succeeds.
    model_info(lists, T, 8, 8);
    g = fresh();
    failNext = 1;
    CHECK(gb_start(&g) == 0);
    CHECK(!strcmp(g.rom_pid, "BERLIN") && !strcmp(g.patch_pid, "9966") && g.patch_vid[3] == 4 && g.sensor_id == 3);
    CHECK(g.touch_addr == T && g.touch_head_len == 8 && g.point_len == 8 && g.config_id == 0x12345678 && g.config_version == 7);
    CHECK(g.drv_num == 36 && g.sen_num == 38 && nwrites == 0);
    // IC information failures: length, checksum, lists running past the end, a touch address outside the window, a layout.
    put16(reg(GB_IC_INFO_ADDR), 2000);
    g = fresh(); CHECK(gb_start(&g) == GB_E_INFO_LENGTH && g.touch_addr == 0);
    unsigned len = model_info(lists, T, 8, 8);
    reg(GB_IC_INFO_ADDR)[len - 1] ^= 0x10;
    g = fresh(); CHECK(gb_start(&g) == GB_E_INFO_CHECKSUM);
    len = model_info(lists, T, 8, 8);
    reg(GB_IC_INFO_ADDR)[32] = 200;            // the first list now claims 200 values: it runs past the block
    seal(reg(GB_IC_INFO_ADDR), len);
    g = fresh(); CHECK(gb_start(&g) == GB_E_INFO_SHORT);
    model_info(lists, 0x13400, 8, 8);
    g = fresh(); CHECK(gb_start(&g) == GB_E_INFO_ADDR && g.touch_addr == 0);
    CHECK(gb_poll(&g, &f) == GB_E_NOT_STARTED);
    model_info(lists, T, 8, 10);
    g = fresh(); CHECK(gb_start(&g) == GB_E_INFO_LAYOUT && g.touch_addr == 0);
    CHECK(nwrites == 0);

    model_info(lists, T, 8, 8);
    g = fresh();
    CHECK(gb_start(&g) == 0);
    // Nothing pending: no clear.
    memset(reg(T), 0, GB_EVENT_MAX);
    CHECK(gb_poll(&g, &f) == 0 && nwrites == 0);
    // One finger.
    uint8_t pts[10][8];
    point(pts[0], 3, 0, 1234, 20000, 40);
    model_event(T, GB_EVENT_TOUCH, 1, pts, 1);
    CHECK(gb_poll(&g, &f) == 1 && f.count == 1 && f.contact[3].active && f.contact[3].x == 1234 && f.contact[3].y == 20000 && f.contact[3].width == 40);
    CHECK(nwrites == 1 && reg(T)[0] == 0);
    CHECK(gb_poll(&g, &f) == 0 && nwrites == 1);              // cleared: nothing new
    // Three fingers: the third point comes from the second read.
    point(pts[0], 0, 0, 10, 20, 5); point(pts[1], 1, 0, 30, 40, 6); point(pts[2], 9, 0, 22679, 24399, 7);
    model_event(T, GB_EVENT_TOUCH, 3, pts, 3);
    const unsigned r0 = nreads;
    CHECK(gb_poll(&g, &f) == 1 && f.count == 3 && f.contact[9].x == 22679 && f.contact[9].y == 24399 && f.contact[1].y == 40);
    CHECK(nreads == r0 + 2);
    // Ten fingers.
    for (unsigned i = 0; i < 10; ++i) point(pts[i], i, 0, 100 * i, 200 * i, i);
    model_event(T, GB_EVENT_TOUCH, 10, pts, 10);
    CHECK(gb_poll(&g, &f) == 1 && f.count == 10 && f.contact[7].x == 700 && f.contact[7].y == 1400);
    // Stylus points and a stylus hover are dropped; a finger next to them is kept.
    point(pts[0], 2, GB_POINT_STYLUS, 5, 5, 1); point(pts[1], 4, 0, 50, 60, 2); point(pts[2], 5, GB_POINT_STYLUS_HOVER, 7, 7, 1);
    model_event(T, GB_EVENT_TOUCH, 3, pts, 3);
    CHECK(gb_poll(&g, &f) == 1 && f.count == 1 && f.contact[4].active && !f.contact[2].active && !f.contact[5].active);
    // Every contact lifted: a touch event with no points.
    model_event(T, GB_EVENT_TOUCH, 0, pts, 0);
    CHECK(gb_poll(&g, &f) == 1 && f.count == 0);
    // Header checksum, point checksum and count failures are cleared and reported.
    point(pts[0], 1, 0, 1, 1, 1);
    model_event(T, GB_EVENT_TOUCH, 1, pts, 1); reg(T)[7] ^= 1;
    unsigned w0 = nwrites;
    CHECK(gb_poll(&g, &f) == GB_E_HEADER && nwrites == w0 + 1);
    model_event(T, GB_EVENT_TOUCH, 1, pts, 1); reg(T)[GB_HEADER_LEN + 9] ^= 1;
    CHECK(gb_poll(&g, &f) == GB_E_POINTS && nwrites == w0 + 2);
    model_event(T, GB_EVENT_TOUCH, 12, pts, 0);
    CHECK(gb_poll(&g, &f) == GB_E_COUNT && nwrites == w0 + 3);
    // Requests: reset asks the caller to reset; config is cleared and otherwise ignored.
    model_event(T, GB_EVENT_REQUEST, GB_REQUEST_RESET, pts, 0);
    CHECK(gb_poll(&g, &f) == 2 && g.request == GB_REQUEST_RESET);
    model_event(T, GB_EVENT_REQUEST, 0x01, pts, 0);
    CHECK(gb_poll(&g, &f) == 0);
    // A gesture event is cleared and reports nothing.
    model_event(T, 0x20, 0, pts, 0);
    CHECK(gb_poll(&g, &f) == 0);
    // A bus failure on the read is reported without a clear.
    w0 = nwrites; failNext = 1;
    CHECK(gb_poll(&g, &f) == GB_E_BUS && nwrites == w0);
    // Decoder edge cases: an id beyond the contacts and a repeated id.
    point(pts[0], 12, 0, 1, 1, 1); point(pts[1], 3, 0, 8, 9, 1); point(pts[2], 3, 0, 70, 70, 1);
    CHECK(gb_decode(pts[0], 3, &f) == 1 && f.contact[3].x == 8);
    // A touch address that changes to one outside the window after start is never written.
    g.touch_addr = 0x13400;
    w0 = nwrites;
    model_event(0x13400, GB_EVENT_TOUCH, 1, pts + 1, 1);
    CHECK(gb_poll(&g, &f) == GB_E_INFO_ADDR && nwrites == w0 && g.refused == 1);

    writes_only_clears(T);
    printf("goodix-berlin: %u reads, %u writes (each a 0 at 0x%05x), all cases pass\n", nreads, nwrites, T);
    return 0;
}
