/*
 * A-OS 兼容层 —— 测试夹具：手工构造最小但严格合法的 arm64 Mach-O
 * 不依赖任何 Apple SDK，纯字节拼装，用于验证解析器与注入器的边界行为。
 * 许可证：GPL-3.0-only
 */
#ifndef AOS_TEST_MACHO_FIXTURE_H
#define AOS_TEST_MACHO_FIXTURE_H

#include "aos_common.h"
#include "aos_macho.h"
#include <stdlib.h>
#include <string.h>

#define TFI_THIN_SIZE    0x2000u   /* 文件总长 8KiB */
#define TFI_SECTION_OFF  0x1000u   /* __text section 的文件偏移 → padding 上界 */
#define TFI_SEG_CMDSIZE  152u      /* 72 + 1×80 */
#define TFI_MAIN_CMDSIZE 24u
#define TFI_HEADER_END   (AOS_SIZEOF_MACH_HEADER_64 + TFI_SEG_CMDSIZE + TFI_MAIN_CMDSIZE)

static void tfi_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

/* thin：2 条 Load Command（__TEXT 段 + LC_MAIN），header 之后留大段 padding */
static uint8_t *tfi_make_thin(size_t *out_len) {
    size_t len = TFI_THIN_SIZE;
    uint8_t *b = (uint8_t *)calloc(1, len);
    if (!b) return NULL;

    aos_wr32(b + 0,  AOS_MH_MAGIC_64);
    aos_wr32(b + 4,  AOS_CPU_TYPE_ARM64);
    aos_wr32(b + 8,  AOS_CPU_SUBTYPE_ARM64_ALL);
    aos_wr32(b + 12, AOS_MH_EXECUTE);
    aos_wr32(b + 16, 2u);
    aos_wr32(b + 20, TFI_SEG_CMDSIZE + TFI_MAIN_CMDSIZE);
    aos_wr32(b + 24, 0u);
    aos_wr32(b + 28, 0u);

    uint8_t *seg = b + AOS_SIZEOF_MACH_HEADER_64;
    aos_wr32(seg + 0, AOS_LC_SEGMENT_64);
    aos_wr32(seg + 4, TFI_SEG_CMDSIZE);
    memcpy(seg + 8, "__TEXT", 7);
    aos_wr64(seg + 24, 0x100000000ULL);   /* vmaddr */
    aos_wr64(seg + 32, 0x2000ULL);        /* vmsize */
    aos_wr64(seg + 40, 0ULL);             /* fileoff */
    aos_wr64(seg + 48, 0x2000ULL);        /* filesize */
    aos_wr32(seg + 56, 7u);               /* maxprot */
    aos_wr32(seg + 60, 5u);               /* initprot = R-X */
    aos_wr32(seg + 64, 1u);               /* nsects */
    aos_wr32(seg + 68, 0u);

    uint8_t *sec = seg + AOS_SIZEOF_SEGMENT_COMMAND_64;
    memcpy(sec + 0, "__text", 7);
    memcpy(sec + 16, "__TEXT", 7);
    aos_wr64(sec + 32, 0x100001000ULL);   /* addr */
    aos_wr64(sec + 40, 0x100ULL);         /* size */
    aos_wr32(sec + 48, TFI_SECTION_OFF);  /* offset */
    aos_wr32(sec + 52, 4u);               /* align */

    uint8_t *mn = b + AOS_SIZEOF_MACH_HEADER_64 + TFI_SEG_CMDSIZE;
    aos_wr32(mn + 0, AOS_LC_MAIN);
    aos_wr32(mn + 4, TFI_MAIN_CMDSIZE);
    aos_wr64(mn + 8, 0x800ULL);           /* entryoff */
    aos_wr64(mn + 16, 0ULL);              /* stacksize */

    /* 真实数据区放魔数，用来验证注入没有搬动任何既有字节 */
    aos_wr32(b + TFI_SECTION_OFF, 0x0A05C0DEu);
    if (out_len) *out_len = len;
    return b;
}

/* fat：把上面的 thin 包进一个只含 arm64 slice 的 FAT 头（大端） */
static uint8_t *tfi_make_fat(size_t *out_len) {
    size_t thin_len = 0;
    uint8_t *thin = tfi_make_thin(&thin_len);
    if (!thin) return NULL;
    uint32_t slice_off = 0x1000u;
    size_t len = (size_t)slice_off + thin_len;
    uint8_t *b = (uint8_t *)calloc(1, len);
    if (!b) { free(thin); return NULL; }

    tfi_be32(b + 0, AOS_FAT_MAGIC);       /* 字节序 CA FE BA BE */
    tfi_be32(b + 4, 1u);                  /* nfat_arch */
    uint8_t *a = b + 8;
    tfi_be32(a + 0,  AOS_CPU_TYPE_ARM64);
    tfi_be32(a + 4,  AOS_CPU_SUBTYPE_ARM64_ALL);
    tfi_be32(a + 8,  slice_off);
    tfi_be32(a + 12, (uint32_t)thin_len);
    tfi_be32(a + 16, 12u);                /* align = 2^12 */
    memcpy(b + slice_off, thin, thin_len);
    free(thin);
    if (out_len) *out_len = len;
    return b;
}

#endif /* AOS_TEST_MACHO_FIXTURE_H */
