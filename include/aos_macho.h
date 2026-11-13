/*
 * A-OS 兼容层 —— Mach-O 解析与 Load Commands 注入
 * 自包含定义，不依赖任何 Apple SDK 头文件（安卓上没有 loader.h）。
 * 许可证：GPL-3.0-only
 */
#ifndef AOS_MACHO_H
#define AOS_MACHO_H

#include "aos_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 魔数 ---- */
#define AOS_MH_MAGIC_64   0xFEEDFACFu   /* 64 位 Mach-O，小端存放时为 CF FA ED FE */
#define AOS_MH_CIGAM_64   0xCFFAEDFEu
#define AOS_FAT_MAGIC     0xCAFEBABEu
#define AOS_FAT_CIGAM     0xBEBAFECAu
#define AOS_FAT_MAGIC_64  0xCAFEBABFu
#define AOS_FAT_CIGAM_64  0xBFBAFECAu

/* ---- CPU ---- */
#define AOS_CPU_TYPE_ARM64     0x0100000Cu
#define AOS_CPU_TYPE_ARM64_32  0x0200000Cu
#define AOS_CPU_SUBTYPE_MASK   0xFF000000u
#define AOS_CPU_SUBTYPE_ARM64E 0x00000002u   /* arm64e：带 PAC，本项目不碰 */
#define AOS_CPU_SUBTYPE_ARM64_ALL 0x00000000u

/* ---- 文件类型 ---- */
#define AOS_MH_EXECUTE 2u
#define AOS_MH_DYLIB   6u
#define AOS_MH_BUNDLE  8u

/* ---- Load Commands ---- */
#define AOS_LC_REQ_DYLD              0x80000000u
#define AOS_LC_SEGMENT_64            0x19u
#define AOS_LC_SYMTAB                0x02u
#define AOS_LC_LOAD_DYLIB            0x0Cu
#define AOS_LC_ID_DYLIB              0x0Du
#define AOS_LC_LOAD_DYLINKER         0x0Eu
#define AOS_LC_LOAD_WEAK_DYLIB      (0x18u | AOS_LC_REQ_DYLD)
#define AOS_LC_RPATH                (0x1Cu | AOS_LC_REQ_DYLD)
#define AOS_LC_CODE_SIGNATURE        0x1Du
#define AOS_LC_REEXPORT_DYLIB       (0x1Fu | AOS_LC_REQ_DYLD)
#define AOS_LC_DYLD_INFO_ONLY       (0x22u | AOS_LC_REQ_DYLD)
#define AOS_LC_ENCRYPTION_INFO_64    0x2Cu
#define AOS_LC_MAIN                 (0x28u | AOS_LC_REQ_DYLD)
#define AOS_LC_BUILD_VERSION         0x32u
#define AOS_LC_DYLD_CHAINED_FIXUPS  (0x34u | AOS_LC_REQ_DYLD)

/* ---- 结构尺寸（字节） ---- */
#define AOS_SIZEOF_MACH_HEADER_64        32u
#define AOS_SIZEOF_LOAD_COMMAND           8u
#define AOS_SIZEOF_SEGMENT_COMMAND_64    72u
#define AOS_SIZEOF_SECTION_64            80u
#define AOS_SIZEOF_DYLIB_COMMAND         24u
#define AOS_SIZEOF_ENTRY_POINT_COMMAND   24u
#define AOS_SIZEOF_FAT_ARCH              20u
#define AOS_SIZEOF_FAT_ARCH_64           32u

#define AOS_SEG_TEXT  "__TEXT"
#define AOS_SEG_DATA  "__DATA"
#define AOS_SEG_LINKEDIT "__LINKEDIT"

/* ---- 解析结果 ---- */
typedef struct {
    const uint8_t *base;      /* 指向选中 slice 的起始（不拥有内存） */
    size_t         size;      /* slice 长度 */
    uint32_t       cpu_type;
    uint32_t       cpu_subtype;
    uint32_t       filetype;
    uint32_t       ncmds;
    uint32_t       sizeofcmds;
    uint32_t       flags;
    int            is_arm64e;      /* 1 = arm64e（有 PAC），0 = 普通 arm64 */
    int            is_encrypted;   /* 1 = 仍带 FairPlay 加密，砸壳没砸干净 */
    int            has_chained_fixups; /* iOS 15+ 的 LC_DYLD_CHAINED_FIXUPS */
    uint64_t       entryoff;       /* LC_MAIN */
    uint64_t       text_vmaddr;    /* __TEXT 首选加载地址 */
    uint64_t       text_vmsize;
    uint64_t       min_fileoff;    /* 所有 segment 中最小的 fileoff */
    uint64_t       first_section_off; /* 第一个 section 的文件偏移：注入可用空白的上界 */
    uint32_t       header_end;     /* 32 + sizeofcmds */
} aos_macho_image_t;

typedef int (*aos_lc_visitor_t)(uint32_t cmd, uint32_t cmdsize,
                                const uint8_t *lc, void *ctx);

/* 打开一个 thin arm64 Mach-O（或 fat 中的 arm64 slice，取第一个匹配）。
 * 只做边界校验，不复制内存；img.base 借用的是入参 buf。 */
int aos_macho_open(const uint8_t *buf, size_t len, aos_macho_image_t *out);

/* 遍历全部 Load Commands，回调返回非 0 立即停止 */
int aos_macho_foreach_lc(const aos_macho_image_t *img,
                         aos_lc_visitor_t fn, void *ctx);

/* 读取某条 dylib_command 里的路径字符串（返回指向 buf 内部的指针） */
const char *aos_dylib_path(const uint8_t *lc, uint32_t cmdsize);

/* 从 fat 中提取 arm64 slice，输出为独立 thin 镜像（新分配内存，需 aos_free） */
int aos_macho_extract_arm64(const uint8_t *buf, size_t len,
                            uint8_t **out_buf, size_t *out_len);

/* 核心：向砸壳包的 header padding 区插入 LC_LOAD_DYLIB。
 * 不改动 __TEXT 内容、不整体搬移文件；只吃 linker 预留的空白。
 * 输出新缓冲区（调用方 aos_free）。失败返回负码。 */
int aos_macho_inject_dylib(const uint8_t *buf, size_t len,
                           const char *dylib_path, uint32_t lc_cmd,
                           uint8_t **out_buf, size_t *out_len);

/* 累计当前已有的 dylib 注入数量 */
int aos_macho_count_injections(const aos_macho_image_t *img,
                               const char *dylib_path);

/* 人类可读的 Load Command 名（中文） */
const char *aos_lc_name(uint32_t cmd);

#ifdef __cplusplus
}
#endif
#endif /* AOS_MACHO_H */
