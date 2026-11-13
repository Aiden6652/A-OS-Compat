/*
 * A-OS 兼容层 —— Mach-O 解析
 * 严格边界校验：所有 Load Command 都要检查 cmdsize >= 8、8 字节对齐、不越界。
 * 许可证：GPL-3.0-only
 */
#include "aos_macho.h"
#include <stdlib.h>
#include <limits.h>

/* fat 头是大端；用显式字节判断魔数，避免主机字节序歧义 */
static int fat_is_magic(const uint8_t *p, int *is_64) {
    if (p[0] == 0xCA && p[1] == 0xFE && p[2] == 0xBA && p[3] == 0xBE) {
        *is_64 = 0; return 1;
    }
    if (p[0] == 0xCA && p[1] == 0xFE && p[2] == 0xBA && p[3] == 0xBF) {
        *is_64 = 1; return 1;
    }
    return 0;
}
static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}
static uint64_t be64(const uint8_t *p) {
    uint64_t v = 0; for (int i = 0; i < 8; i++) v = (v << 8) | p[i]; return v;
}

/* 把某个 slice 的字段填进 img */
static int fill_thin(const uint8_t *base, size_t size, aos_macho_image_t *out) {
    if (size < AOS_SIZEOF_MACH_HEADER_64) return AOS_ERR_BAD_FORMAT;
    memset(out, 0, sizeof(*out));
    out->base      = base;
    out->size      = size;
    out->cpu_type    = aos_rd32(base + 4);
    out->cpu_subtype = aos_rd32(base + 8);
    out->filetype    = aos_rd32(base + 12);
    out->ncmds       = aos_rd32(base + 16);
    out->sizeofcmds  = aos_rd32(base + 20);
    out->flags       = aos_rd32(base + 24);
    out->header_end  = AOS_SIZEOF_MACH_HEADER_64 + out->sizeofcmds;
    out->min_fileoff = UINT64_MAX;
    out->first_section_off = UINT64_MAX;

    if (out->cpu_type != AOS_CPU_TYPE_ARM64) return AOS_ERR_UNSUPPORTED;
    if (((out->cpu_subtype & 0x00FFFFFFu) == AOS_CPU_SUBTYPE_ARM64E))
        out->is_arm64e = 1;
    if ((uint64_t)out->header_end > size) return AOS_ERR_BAD_FORMAT;

    const uint8_t *lc = base + AOS_SIZEOF_MACH_HEADER_64;
    uint64_t remain = out->sizeofcmds;
    for (uint32_t i = 0; i < out->ncmds; i++) {
        if (remain < AOS_SIZEOF_LOAD_COMMAND) return AOS_ERR_BAD_FORMAT;
        uint32_t cmd     = aos_rd32(lc);
        uint32_t cmdsize = aos_rd32(lc + 4);
        if (cmdsize < AOS_SIZEOF_LOAD_COMMAND || (cmdsize & 7u) ||
            cmdsize > remain) return AOS_ERR_BAD_FORMAT;

        switch (cmd) {
            case AOS_LC_SEGMENT_64: {
                if (cmdsize < AOS_SIZEOF_SEGMENT_COMMAND_64) return AOS_ERR_BAD_FORMAT;
                uint64_t vmaddr  = aos_rd64(lc + 24);
                uint64_t vmsize  = aos_rd64(lc + 32);
                uint64_t fileoff = aos_rd64(lc + 40);
                uint32_t nsects  = aos_rd32(lc + 64);
                if (!memcmp(lc + 8, AOS_SEG_TEXT, 5)) {
                    out->text_vmaddr = vmaddr;
                    out->text_vmsize = vmsize;
                }
                if (fileoff < out->min_fileoff) out->min_fileoff = fileoff;
                /* 遍历 section，找最小的文件偏移 */
                if ((uint64_t)AOS_SIZEOF_SEGMENT_COMMAND_64 +
                    (uint64_t)nsects * AOS_SIZEOF_SECTION_64 > cmdsize)
                    return AOS_ERR_BAD_FORMAT;
                const uint8_t *sec = lc + AOS_SIZEOF_SEGMENT_COMMAND_64;
                for (uint32_t s = 0; s < nsects; s++, sec += AOS_SIZEOF_SECTION_64) {
                    uint32_t off = aos_rd32(sec + 48);
                    if (off > 0 && off < out->first_section_off)
                        out->first_section_off = off;
                }
                break;
            }
            case AOS_LC_MAIN:
                if (cmdsize < 16) return AOS_ERR_BAD_FORMAT;
                out->entryoff = aos_rd64(lc + 8);
                break;
            case AOS_LC_ENCRYPTION_INFO_64:
                if (cmdsize < 20) return AOS_ERR_BAD_FORMAT;
                if (aos_rd32(lc + 16) != 0) out->is_encrypted = 1; /* cryptid */
                break;
            case AOS_LC_DYLD_CHAINED_FIXUPS:
                out->has_chained_fixups = 1;
                break;
            default:
                break;
        }
        lc     += cmdsize;
        remain -= cmdsize;
    }
    if (remain != 0) return AOS_ERR_BAD_FORMAT;
    return AOS_OK;
}

int aos_macho_open(const uint8_t *buf, size_t len, aos_macho_image_t *out) {
    if (!buf || !out || len < 4) return AOS_ERR_INVALID_ARG;

    uint32_t magic = aos_rd32(buf);
    if (magic == AOS_MH_MAGIC_64) {
        return fill_thin(buf, len, out);
    }
    if (magic == AOS_MH_CIGAM_64) {
        return AOS_ERR_UNSUPPORTED; /* 大端 Mach-O，iOS 不存在 */
    }

    int is_64 = 0;
    if (!fat_is_magic(buf, &is_64)) return AOS_ERR_BAD_MAGIC;

    uint32_t nfat = be32(buf + 4);
    size_t   ent  = is_64 ? AOS_SIZEOF_FAT_ARCH_64 : AOS_SIZEOF_FAT_ARCH;
    if ((uint64_t)nfat * ent + 8 > len) return AOS_ERR_BAD_FORMAT;

    for (uint32_t i = 0; i < nfat; i++) {
        const uint8_t *a = buf + 8 + (size_t)i * ent;
        uint32_t cputype    = be32(a);
        uint32_t cpusubtype = be32(a + 4);
        uint64_t off        = is_64 ? be64(a + 8)  : be32(a + 8);
        uint64_t sz         = is_64 ? be64(a + 16) : be32(a + 12);
        if (cputype != AOS_CPU_TYPE_ARM64) continue;
        if ((cpusubtype & 0x00FFFFFFu) == AOS_CPU_SUBTYPE_ARM64E) continue;
        if (off > len || sz > len - off || sz < AOS_SIZEOF_MACH_HEADER_64)
            return AOS_ERR_BAD_FORMAT;
        return fill_thin(buf + off, (size_t)sz, out);
    }
    return AOS_ERR_UNSUPPORTED; /* fat 里没有普通 arm64 slice */
}

int aos_macho_foreach_lc(const aos_macho_image_t *img,
                         aos_lc_visitor_t fn, void *ctx) {
    if (!img || !img->base || !fn) return AOS_ERR_INVALID_ARG;
    const uint8_t *lc = img->base + AOS_SIZEOF_MACH_HEADER_64;
    uint64_t remain = img->sizeofcmds;
    for (uint32_t i = 0; i < img->ncmds; i++) {
        uint32_t cmd     = aos_rd32(lc);
        uint32_t cmdsize = aos_rd32(lc + 4);
        if (cmdsize < 8 || cmdsize > remain) return AOS_ERR_BAD_FORMAT;
        int rc = fn(cmd, cmdsize, lc, ctx);
        if (rc != AOS_OK) return rc;
        lc += cmdsize; remain -= cmdsize;
    }
    return AOS_OK;
}

const char *aos_dylib_path(const uint8_t *lc, uint32_t cmdsize) {
    if (!lc || cmdsize < AOS_SIZEOF_DYLIB_COMMAND) return NULL;
    uint32_t name_off = aos_rd32(lc + 8); /* dylib.name */
    if (name_off < AOS_SIZEOF_DYLIB_COMMAND || name_off >= cmdsize) return NULL;
    const char *s = (const char *)(lc + name_off);
    size_t avail = cmdsize - name_off;
    if (!memchr(s, '\0', avail)) return NULL;
    return s;
}

const char *aos_lc_name(uint32_t cmd) {
    switch (cmd) {
        case AOS_LC_SEGMENT_64:            return "LC_SEGMENT_64（段映射）";
        case AOS_LC_SYMTAB:                return "LC_SYMTAB（符号表）";
        case AOS_LC_LOAD_DYLIB:            return "LC_LOAD_DYLIB（依赖动态库）";
        case AOS_LC_ID_DYLIB:              return "LC_ID_DYLIB";
        case AOS_LC_LOAD_DYLINKER:         return "LC_LOAD_DYLINKER（dyld 路径）";
        case AOS_LC_LOAD_WEAK_DYLIB:       return "LC_LOAD_WEAK_DYLIB（弱依赖）";
        case AOS_LC_RPATH:                 return "LC_RPATH（搜索路径）";
        case AOS_LC_CODE_SIGNATURE:        return "LC_CODE_SIGNATURE（签名）";
        case AOS_LC_REEXPORT_DYLIB:        return "LC_REEXPORT_DYLIB";
        case AOS_LC_DYLD_INFO_ONLY:        return "LC_DYLD_INFO_ONLY（经典 fixups）";
        case AOS_LC_ENCRYPTION_INFO_64:    return "LC_ENCRYPTION_INFO_64（加密标记）";
        case AOS_LC_MAIN:                  return "LC_MAIN（入口点）";
        case AOS_LC_BUILD_VERSION:         return "LC_BUILD_VERSION（平台版本）";
        case AOS_LC_DYLD_CHAINED_FIXUPS:   return "LC_DYLD_CHAINED_FIXUPS（链式修正）";
        default:                           return "未知 Load Command";
    }
}

int aos_macho_extract_arm64(const uint8_t *buf, size_t len,
                            uint8_t **out_buf, size_t *out_len) {
    if (!buf || !out_buf || !out_len) return AOS_ERR_INVALID_ARG;
    *out_buf = NULL; *out_len = 0;

    aos_macho_image_t img;
    int rc = aos_macho_open(buf, len, &img);
    if (rc != AOS_OK) return rc;

    /* thin 也复制一份，让调用方统一拥有内存 */
    uint8_t *copy = (uint8_t *)aos_alloc(img.size);
    if (!copy) return AOS_ERR_NO_MEM;
    memcpy(copy, img.base, img.size);
    *out_buf = copy; *out_len = img.size;
    return AOS_OK;
}

int aos_macho_count_injections(const aos_macho_image_t *img,
                               const char *dylib_path) {
    if (!img || !dylib_path) return 0;
    int count = 0;
    const uint8_t *lc = img->base + AOS_SIZEOF_MACH_HEADER_64;
    uint64_t remain = img->sizeofcmds;
    for (uint32_t i = 0; i < img->ncmds; i++) {
        uint32_t cmd = aos_rd32(lc), sz = aos_rd32(lc + 4);
        if (sz < 8 || sz > remain) break;
        if (cmd == AOS_LC_LOAD_DYLIB || cmd == AOS_LC_LOAD_WEAK_DYLIB) {
            const char *p = aos_dylib_path(lc, sz);
            if (p && !strcmp(p, dylib_path)) count++;
        }
        lc += sz; remain -= sz;
    }
    return count;
}
