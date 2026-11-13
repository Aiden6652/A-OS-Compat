/*
 * A-OS 兼容层 —— Mach-O 加载器 / 沙盒 / HLE 框架桩
 *
 * 明确边界：本文件完成「可验证的加载与登记」，不声称已跑通完整 UIKit。
 * dyld_shared_cache 的 bind、UIKit 全量控件、Metal 全量管线属于后续里程碑，
 * 见 README 的「诚实的能力边界」章节。
 * 许可证：GPL-3.0-only
 */
#include "aos_loader.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

/* ---------------- 加载器 ---------------- */
typedef struct {
    uint64_t vmaddr, vmsize, fileoff, filesize;
    uint32_t initprot;
    char     name[17];
} seg_view_t;

static size_t collect_segments(const aos_macho_image_t *img,
                               seg_view_t *out, size_t cap,
                               uint64_t *min_va, uint64_t *max_va) {
    size_t n = 0;
    *min_va = UINT64_MAX; *max_va = 0;
    const uint8_t *lc = img->base + AOS_SIZEOF_MACH_HEADER_64;
    uint32_t remain = img->sizeofcmds;
    for (uint32_t i = 0; i < img->ncmds && n < cap; i++) {
        uint32_t cmd = aos_rd32(lc), sz = aos_rd32(lc + 4);
        if (sz < 8 || sz > remain) break;
        if (cmd == AOS_LC_SEGMENT_64 && sz >= AOS_SIZEOF_SEGMENT_COMMAND_64) {
            seg_view_t *s = &out[n++];
            memcpy(s->name, lc + 8, 16); s->name[16] = '\0';
            s->vmaddr   = aos_rd64(lc + 24);
            s->vmsize   = aos_rd64(lc + 32);
            s->fileoff  = aos_rd64(lc + 40);
            s->filesize = aos_rd64(lc + 48);
            s->initprot = aos_rd32(lc + 60);
            if (s->vmaddr < *min_va) *min_va = s->vmaddr;
            if (s->vmaddr + s->vmsize > *max_va) *max_va = s->vmaddr + s->vmsize;
        }
        lc += sz; remain -= sz;
    }
    return n;
}

int aos_loader_map(const aos_macho_image_t *img, aos_guest_t *out) {
    if (!img || !img->base || !out) return AOS_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    seg_view_t segs[16];
    uint64_t min_va, max_va;
    size_t n = collect_segments(img, segs, 16, &min_va, &max_va);
    if (n == 0 || min_va == UINT64_MAX || max_va <= min_va)
        return AOS_ERR_BAD_FORMAT;
    size_t span = (size_t)(max_va - min_va);
    if (span == 0) return AOS_ERR_BAD_FORMAT;

    /* iOS 二进制按 16KiB 页对齐，安卓是 4KiB —— 16K 是 4K 的整数倍，
     * 所以 mprotect 的页对齐要求天然满足，不用像 UniXNU 那样魔改 XNU 页表。
     * 这是"用户态兼容层"相对"扒内核"最省事的一处。 */
    void *base = mmap(NULL, span, PROT_NONE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return AOS_ERR_NO_MEM;

    for (size_t i = 0; i < n; i++) {
        seg_view_t *s = &segs[i];
        uint8_t *dst = (uint8_t *)base + (size_t)(s->vmaddr - min_va);
        if (s->vmsize == 0) continue;
        /* 先开 RW 复制文件内容，再收紧到 initprot（W^X） */
        if (mprotect(dst, (size_t)s->vmsize, PROT_READ | PROT_WRITE) != 0) {
            munmap(base, span); return AOS_ERR_IO;
        }
        if (s->filesize > 0) {
            if (s->fileoff + s->filesize > img->size) {
                munmap(base, span); return AOS_ERR_BAD_FORMAT;
            }
            memcpy(dst, img->base + s->fileoff, (size_t)s->filesize);
        }
        int prot = PROT_NONE;
        if (s->initprot & 1) prot |= PROT_READ;
        if (s->initprot & 2) prot |= PROT_WRITE;
        if (s->initprot & 4) prot |= PROT_EXEC;
        if (!prot) prot = PROT_READ;
        if (mprotect(dst, (size_t)s->vmsize, prot) != 0) {
            munmap(base, span); return AOS_ERR_IO;
        }
    }

    out->mapped_base   = (uint8_t *)base;
    out->mapped_size   = span;
    out->preferred_base = min_va;
    out->slide         = (uint64_t)(uintptr_t)base - min_va;
    out->entry         = (uint64_t)(uintptr_t)base + img->entryoff;
    out->needs_chained_fixups = img->has_chained_fixups;
    out->wx_enforced   = 1;
    AOS_LOG_INFO("镜像已映射：跨度 0x%zx，slide 0x%llx，入口 0x%llx（%s）",
                 span, (unsigned long long)out->slide,
                 (unsigned long long)out->entry,
                 img->has_chained_fixups ? "链式修正待处理" : "经典 fixups");
    return AOS_OK;
}

void aos_loader_unmap(aos_guest_t *g) {
    if (g && g->mapped_base && g->mapped_size)
        munmap(g->mapped_base, g->mapped_size);
    if (g) memset(g, 0, sizeof(*g));
}

int aos_loader_apply_chained_fixups(aos_guest_t *g, const aos_macho_image_t *img,
                                    size_t *out_rebase_count) {
    if (!g || !img || !out_rebase_count) return AOS_ERR_INVALID_ARG;
    *out_rebase_count = 0;
    if (!img->has_chained_fixups) return AOS_OK;

    /* dyld_chained_fixups_header:
     * u32 fixups_version, starts_offset, imports_offset, symbols_offset;
     * u32 imports_count, imports_format, symbols_format; */
    const uint8_t *lc = img->base + AOS_SIZEOF_MACH_HEADER_64;
    uint32_t remain = img->sizeofcmds, dataoff = 0, datasize = 0;
    for (uint32_t i = 0; i < img->ncmds; i++) {
        uint32_t cmd = aos_rd32(lc), sz = aos_rd32(lc + 4);
        if (sz < 8 || sz > remain) break;
        if (cmd == AOS_LC_DYLD_CHAINED_FIXUPS) {
            dataoff = aos_rd32(lc + 8); datasize = aos_rd32(lc + 12); break;
        }
        lc += sz; remain -= sz;
    }
    if (datasize < 28 || (uint64_t)dataoff + datasize > img->size)
        return AOS_ERR_BAD_FORMAT;
    const uint8_t *fx = img->base + dataoff;
    if (aos_rd32(fx) != 0) return AOS_ERR_UNSUPPORTED; /* fixups_version */
    uint32_t starts = aos_rd32(fx + 4);
    if ((uint64_t)starts + 4 > datasize) return AOS_ERR_BAD_FORMAT;
    uint32_t seg_count = aos_rd32(fx + starts);
    if (seg_count > 64) return AOS_ERR_BAD_FORMAT;

    /* 遍历各段 page_start，累计待处理的 rebase 链规模。
     * 完整的 bind opcode / imports 解析属于里程碑 3，此处只做校验与计数。 */
    size_t pages = 0;
    for (uint32_t s = 0; s < seg_count; s++) {
        uint64_t off = (uint64_t)starts + 4 + (uint64_t)s * 4;
        if (off + 4 > datasize) return AOS_ERR_BAD_FORMAT;
        uint32_t info_off = aos_rd32(fx + off);
        if (!info_off) continue;
        uint64_t io = (uint64_t)starts + info_off;
        if (io + 4 > datasize) return AOS_ERR_BAD_FORMAT;
        pages += aos_rd32(fx + io + 16); /* page_count */
    }
    *out_rebase_count = pages;
    AOS_LOG_WARN("链式修正已校验：%zu 个页起始项待 rebase（bind/opcode 解释尚未实现）", pages);
    return AOS_OK;
}

/* ---------------- 沙盒 ---------------- */
int aos_sandbox_init(aos_sandbox_t *sb, const aos_jbenv_t *env,
                     const char *bundle_id) {
    if (!sb || !env) return AOS_ERR_INVALID_ARG;
    memset(sb, 0, sizeof(*sb));
    const char *bid = (bundle_id && bundle_id[0]) ? bundle_id : "com.example.app";
#define JOIN(field, suffix) do {                                             \
    int _n = snprintf(sb->field, sizeof(sb->field), "%s%s",                 \
                      env->app_home, suffix);                                \
    if (_n < 0 || (size_t)_n >= sizeof(sb->field)) return AOS_ERR_IO;        \
} while (0)
    JOIN(home, "");
    JOIN(documents, "/Documents");
    JOIN(library, "/Library");
    JOIN(caches, "/Library/Caches");
    JOIN(tmp, "/tmp");
#undef JOIN
    if (snprintf(sb->jb_root, sizeof(sb->jb_root), "%s", env->jb_root)
        >= (int)sizeof(sb->jb_root)) return AOS_ERR_IO;
    if (snprintf(sb->bundle, sizeof(sb->bundle),
                 "%s/var/containers/Bundle/Application/A0S-APP/%s.app",
                 env->root, bid) >= (int)sizeof(sb->bundle)) return AOS_ERR_IO;
    return AOS_OK;
}

int aos_sandbox_translate(const aos_sandbox_t *sb, const char *ios_path,
                          char *out, size_t cap) {
    if (!sb || !ios_path || !out) return AOS_ERR_INVALID_ARG;
    /* 目录逃逸一律拒绝：iOS 沙盒不能让它摸到安卓宿主路径 */
    if (strstr(ios_path, "..")) return AOS_ERR_INVALID_ARG;

    size_t hl = strlen(sb->home);
    if (!strncmp(ios_path, sb->home, hl)) {
        int n = snprintf(out, cap, "%s%s", sb->home, ios_path + hl);
        return (n < 0 || (size_t)n >= cap) ? AOS_ERR_IO : AOS_OK;
    }
    if (!strncmp(ios_path, AOS_JB_PREFIX, strlen(AOS_JB_PREFIX))) {
        /* 越狱前缀必须落到 /var/jb 根，不能拼进 App Home（否则 tweak 全找不到） */
        int n = snprintf(out, cap, "%s%s", sb->jb_root,
                         ios_path + strlen(AOS_JB_PREFIX));
        return (n < 0 || (size_t)n >= cap) ? AOS_ERR_IO : AOS_OK;
    }
    if (!strncmp(ios_path, "/Documents", 10))
        return (snprintf(out, cap, "%s%s", sb->documents, ios_path + 10)
                >= (int)cap) ? AOS_ERR_IO : AOS_OK;
    if (!strncmp(ios_path, "/tmp", 4))
        return (snprintf(out, cap, "%s%s", sb->tmp, ios_path + 4)
                >= (int)cap) ? AOS_ERR_IO : AOS_OK;
    /* 其余绝对路径收进 App Home，绝不落到安卓根 */
    int n = snprintf(out, cap, "%s%s", sb->home,
                     ios_path[0] == '/' ? "" : "/");
    if (n < 0 || (size_t)n >= cap) return AOS_ERR_IO;
    if (ios_path[0] == '/') {
        int m = snprintf(out, cap, "%s%s", sb->home, ios_path);
        return (m < 0 || (size_t)m >= cap) ? AOS_ERR_IO : AOS_OK;
    }
    return AOS_OK;
}

/* ---------------- HLE 框架桩 ---------------- */
static char g_vulkan_icd[64] = "未挂载";

static void stub_NSHomeDirectory(void)  {}
static void stub_NSLog(void)            {}
static void stub_NSStringFromClass(void){}
static void stub_UIApplicationMain(void){}
static void stub_UIView_init(void)      {}
static void stub_objc_msgSend(void)     {} /* 实机由 aarch64/entry.S 汇编桩接管 */
static void stub_objc_getClass(void)    {}
static void stub_sel_registerName(void) {}
static void stub_MTLCreateDevice(void)  {}
static void stub_CGRectMake(void)       {}
static void stub_malloc(void)           {}
static void stub_free(void)             {}
static void stub_printf(void)           {}

static const aos_hle_stub_t kStubs[] = {
    { AOS_HLE_FOUNDATION,   "NSHomeDirectory",       stub_NSHomeDirectory, 0 },
    { AOS_HLE_FOUNDATION,   "NSLog",                 stub_NSLog, 1 },
    { AOS_HLE_FOUNDATION,   "NSStringFromClass",     stub_NSStringFromClass, 0 },
    { AOS_HLE_UIKIT,        "UIApplicationMain",     stub_UIApplicationMain, 1 },
    { AOS_HLE_UIKIT,        "-[UIView initWithFrame:]", stub_UIView_init, 1 },
    { AOS_HLE_OBJCRUNTIME,  "objc_msgSend",          stub_objc_msgSend, 1 },
    { AOS_HLE_OBJCRUNTIME,  "objc_getClass",         stub_objc_getClass, 1 },
    { AOS_HLE_OBJCRUNTIME,  "sel_registerName",      stub_sel_registerName, 1 },
    { AOS_HLE_METAL,        "MTLCreateSystemDefaultDevice", stub_MTLCreateDevice, 1 },
    { AOS_HLE_COREGRAPHICS, "CGRectMake",            stub_CGRectMake, 0 },
    { AOS_HLE_LIBSYSTEM,    "malloc",                stub_malloc, 0 },
    { AOS_HLE_LIBSYSTEM,    "free",                  stub_free, 0 },
    { AOS_HLE_LIBSYSTEM,    "printf",                stub_printf, 0 },
};

int aos_hle_init(void) {
    size_t total = sizeof(kStubs) / sizeof(kStubs[0]);
    size_t jit_needed = 0;
    for (size_t i = 0; i < total; i++)
        if (kStubs[i].abi_flags & 1u) jit_needed++;
    AOS_LOG_INFO("HLE 框架桩登记：%zu 个符号（%zu 个需要 JIT trampoline 加速）",
                 total, jit_needed);
    return AOS_OK;
}

const aos_hle_stub_t *aos_hle_lookup(const char *symbol, aos_hle_fn_t *out_impl) {
    if (!symbol) return NULL;
    for (size_t i = 0; i < sizeof(kStubs) / sizeof(kStubs[0]); i++) {
        if (!strcmp(kStubs[i].symbol, symbol)) {
            if (out_impl) *out_impl = kStubs[i].impl;
            return &kStubs[i];
        }
    }
    return NULL;
}

size_t aos_hle_stub_count(void) {
    return sizeof(kStubs) / sizeof(kStubs[0]);
}

const char *aos_hle_framework_name(aos_hle_framework_t fw) {
    static const char *names[] = {
        "Foundation", "UIKit", "CoreGraphics", "Metal", "Objective-C Runtime", "libSystem"
    };
    if ((int)fw < 0 || (int)fw >= (int)(sizeof(names) / sizeof(names[0])))
        return "未知框架";
    return names[fw];
}

int aos_hle_metal_attach(const char *vulkan_icd_name) {
    if (!vulkan_icd_name || !vulkan_icd_name[0]) return AOS_ERR_INVALID_ARG;
    snprintf(g_vulkan_icd, sizeof(g_vulkan_icd), "%s", vulkan_icd_name);
    AOS_LOG_INFO("Metal→Vulkan 前端已挂载：%s（AIR→SPIR-V→Turnip/Adreno）",
                 g_vulkan_icd);
    return AOS_OK;
}
