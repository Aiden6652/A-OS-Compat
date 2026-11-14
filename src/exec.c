/*
 * A-OS 兼容层 —— 执行引擎实现
 *
 * 关键点：guest 的 arm64 机器码【不解释、不翻译、不模拟】。
 * 我们只在加载时把 ABI 边界（svc #0x80）用 JIT 生成的跳板替换掉，
 * 之后所有指令都由硬件原生执行；跳板把 XNU 调用交给宿主裁决再 br 回 guest。
 *
 * 许可证：GPL-3.0-only
 */
#define _GNU_SOURCE 1
#include "aos_exec.h"
#include "aos_jit.h"
#include "aos_syscall.h"
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <errno.h>
#ifdef __ANDROID__
#include <android/log.h>
#endif

typedef struct {
    uint64_t vmaddr, vmsize, fileoff, filesize;
    uint32_t initprot, nsects;
} seg_t;

static jmp_buf  *g_exit_jmp = NULL;   /* guest exit → longjmp 回宿主 */
static uint64_t  g_trap_count = 0;

/* ---------- segment 收集（与 loader.c 同一套相对偏移规则） ---------- */
static size_t collect_segs(const aos_macho_image_t *img, seg_t *out, size_t cap,
                           uint64_t *min_va, uint64_t *max_va) {
    size_t n = 0;
    *min_va = UINT64_MAX; *max_va = 0;
    const uint8_t *lc = img->base + AOS_SIZEOF_MACH_HEADER_64;
    uint32_t rem = img->sizeofcmds;
    for (uint32_t i = 0; i < img->ncmds && n < cap; i++) {
        uint32_t cmd = aos_rd32(lc), sz = aos_rd32(lc + 4);
        if (sz < 8 || sz > rem) break;
        if (cmd == AOS_LC_SEGMENT_64 && sz >= AOS_SIZEOF_SEGMENT_COMMAND_64) {
            seg_t *s = &out[n++];
            s->vmaddr   = aos_rd64(lc + 24);
            s->vmsize   = aos_rd64(lc + 32);
            s->fileoff  = aos_rd64(lc + 40);
            s->filesize = aos_rd64(lc + 48);
            s->initprot = aos_rd32(lc + 60);
            s->nsects   = aos_rd32(lc + 64);
            if (s->vmaddr < *min_va) *min_va = s->vmaddr;
            if (s->vmaddr + s->vmsize > *max_va) *max_va = s->vmaddr + s->vmsize;
        }
        lc += sz; rem -= sz;
    }
    return n;
}

/* 文件偏移 → guest 运行地址 */
static uint64_t off_to_addr(const aos_macho_image_t *img,
                            const aos_exec_t *ex, uint64_t off) {
    seg_t segs[16]; uint64_t mn, mx;
    size_t n = collect_segs(img, segs, 16, &mn, &mx);
    for (size_t i = 0; i < n; i++)
        if (off >= segs[i].fileoff && off < segs[i].fileoff + segs[i].filesize)
            return (uint64_t)(uintptr_t)ex->guest_base
                   + (segs[i].vmaddr - ex->min_vmaddr)
                   + (off - segs[i].fileoff);
    return (uint64_t)(uintptr_t)ex->guest_base + off;
}

/* ---------- 陷阱扫描 ---------- */
int aos_exec_scan_traps(const aos_macho_image_t *img,
                        uint32_t *sites, size_t cap, size_t *out_count) {
    if (!img || !img->base || !sites || !out_count) return AOS_ERR_INVALID_ARG;
    *out_count = 0;
    const uint8_t *lc = img->base + AOS_SIZEOF_MACH_HEADER_64;
    uint32_t rem = img->sizeofcmds;
    for (uint32_t i = 0; i < img->ncmds; i++) {
        uint32_t cmd = aos_rd32(lc), sz = aos_rd32(lc + 4);
        if (sz < 8 || sz > rem) break;
        if (cmd == AOS_LC_SEGMENT_64 && sz >= AOS_SIZEOF_SEGMENT_COMMAND_64) {
            uint32_t initprot = aos_rd32(lc + 60);
            uint32_t nsects   = aos_rd32(lc + 64);
            if (initprot & 4u) {   /* VM_PROT_EXECUTE：只扫可执行段 */
                const uint8_t *sec = lc + AOS_SIZEOF_SEGMENT_COMMAND_64;
                for (uint32_t s = 0; s < nsects; s++, sec += AOS_SIZEOF_SECTION_64) {
                    if ((uint64_t)AOS_SIZEOF_SEGMENT_COMMAND_64 +
                        (uint64_t)(s + 1) * AOS_SIZEOF_SECTION_64 > sz) break;
                    uint64_t sec_size = aos_rd64(sec + 40);
                    uint32_t sec_off  = aos_rd32(sec + 48);
                    uint64_t begin = sec_off, end = sec_off + sec_size;
                    if (begin < img->header_end) begin = img->header_end;
                    if (end > img->size) end = img->size;
                    for (uint64_t p = begin; p + 4 <= end; p += 4) {
                        if (aos_rd32(img->base + p) == AOS_A64_SVC_80) {
                            if (*out_count < cap) sites[*out_count] = (uint32_t)p;
                            (*out_count)++;
                        }
                    }
                }
            }
        }
        lc += sz; rem -= sz;
    }
    return AOS_OK;
}

/* ---------- 映射：guest 与桩区一次性相邻 mmap ---------- */
int aos_exec_map(const aos_macho_image_t *img, aos_exec_t *ex) {
    if (!img || !img->base || !ex) return AOS_ERR_INVALID_ARG;
    memset(ex, 0, sizeof(*ex));

    seg_t segs[16]; uint64_t min_va, max_va;
    size_t n = collect_segs(img, segs, 16, &min_va, &max_va);
    if (n == 0 || max_va <= min_va) return AOS_ERR_BAD_FORMAT;
    size_t span = (size_t)(max_va - min_va);

    size_t found = 0;
    int rc = aos_exec_scan_traps(img, ex->sites, AOS_EXEC_MAX_SITES, &found);
    if (rc != AOS_OK) return rc;
    ex->site_count = found > AOS_EXEC_MAX_SITES ? AOS_EXEC_MAX_SITES : found;

    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) return AOS_ERR_IO;
    size_t page = (size_t)ps;
    size_t stub_off  = (span + page - 1) / page * page;   /* 桩区页对齐紧随 guest */
    size_t stub_used = (5 + ex->site_count * 5) * sizeof(uint32_t);
    size_t stub_size = (stub_used + page - 1) / page * page;
    if (stub_size == 0) stub_size = page;

    void *mb = mmap(NULL, stub_off + stub_size, PROT_NONE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mb == MAP_FAILED) return AOS_ERR_NO_MEM;

    ex->map_base    = (uint8_t *)mb;
    ex->map_size    = stub_off + stub_size;
    ex->guest_base  = (uint8_t *)mb;
    ex->guest_span  = span;
    ex->min_vmaddr  = min_va;
    ex->stub_off    = stub_off;
    ex->stub_base   = (uint8_t *)mb + stub_off;
    ex->stub_size   = stub_size;
    ex->stub_used   = stub_used;

    for (size_t i = 0; i < n; i++) {
        seg_t *s = &segs[i];
        if (s->vmsize == 0) continue;
        uint8_t *dst = (uint8_t *)mb + (size_t)(s->vmaddr - min_va);
        if (mprotect(dst, (size_t)s->vmsize, PROT_READ | PROT_WRITE) != 0)
            goto fail;
        if (s->filesize > 0) {
            if (s->fileoff + s->filesize > img->size) goto fail;
            memcpy(dst, img->base + s->fileoff, (size_t)s->filesize);
        }
        int prot = PROT_NONE;
        if (s->initprot & 1) prot |= PROT_READ;
        if (s->initprot & 2) prot |= PROT_WRITE;
        if (s->initprot & 4) prot |= PROT_EXEC;
        if (!prot) prot = PROT_READ;
        if (mprotect(dst, (size_t)s->vmsize, prot) != 0) goto fail;
    }

    if (mprotect(ex->stub_base, stub_size, PROT_READ | PROT_WRITE) != 0) goto fail;

    ex->slide = (uint64_t)(uintptr_t)mb - min_va;
    ex->entry = off_to_addr(img, ex, img->entryoff);
    AOS_LOG_INFO("镜像已映射：跨度 0x%zx，slide 0x%llx，入口 0x%llx，"
                 "发现 %zu 个 XNU 陷阱点",
                 span, (unsigned long long)ex->slide,
                 (unsigned long long)ex->entry, ex->site_count);
    return AOS_OK;

fail:
    aos_exec_unmap(ex);
    return AOS_ERR_IO;
}

void aos_exec_unmap(aos_exec_t *ex) {
    if (ex && ex->map_base && ex->map_size) munmap(ex->map_base, ex->map_size);
    if (ex) memset(ex, 0, sizeof(*ex));
}

/* ---------- JIT 预补丁：svc #0x80 → b <专属跳板> ---------- */
int aos_exec_patch_all(aos_exec_t *ex, const aos_macho_image_t *img,
                       uint64_t handler_addr, size_t *out_patched) {
    if (!ex || !ex->stub_base || !img) return AOS_ERR_INVALID_ARG;
    if (out_patched) *out_patched = 0;
    if (ex->site_count == 0) return AOS_OK;

    uint32_t *c = (uint32_t *)ex->stub_base;
    size_t k = 0;

    /* 共享桩：mov64 x17, handler_addr ; br x17（绝对跳转，不受 ±128MB 限制） */
    c[k++] = aos_emit_movz(17, (uint16_t)(handler_addr & 0xFFFFu), 0);
    c[k++] = aos_emit_movk(17, (uint16_t)((handler_addr >> 16) & 0xFFFFu), 1);
    c[k++] = aos_emit_movk(17, (uint16_t)((handler_addr >> 32) & 0xFFFFu), 2);
    c[k++] = aos_emit_movk(17, (uint16_t)((handler_addr >> 48) & 0xFFFFu), 3);
    c[k++] = aos_emit_br(17);
    uint64_t shared = (uint64_t)(uintptr_t)ex->stub_base;

    long ps = sysconf(_SC_PAGESIZE);
    size_t page = ps > 0 ? (size_t)ps : 4096u;
    size_t patched = 0;

    for (size_t i = 0; i < ex->site_count; i++) {
        uint64_t svc_addr = off_to_addr(img, ex, ex->sites[i]);
        uint64_t ret      = svc_addr + 4;

        /* 每点专属桩：mov64 x9, 返回地址 ; b <共享桩>
         * x9 是 ABI 里的 caller-saved 临时寄存器，用来传返回地址最省事；
         * 用 b 而非 bl，绝不碰 x30（guest 的 lr 必须原样保留）。 */
        c[k++] = aos_emit_movz(9, (uint16_t)(ret & 0xFFFFu), 0);
        c[k++] = aos_emit_movk(9, (uint16_t)((ret >> 16) & 0xFFFFu), 1);
        c[k++] = aos_emit_movk(9, (uint16_t)((ret >> 32) & 0xFFFFu), 2);
        c[k++] = aos_emit_movk(9, (uint16_t)((ret >> 48) & 0xFFFFu), 3);
        uint64_t here = (uint64_t)(uintptr_t)&c[k];
        c[k++] = aos_emit_b((int32_t)((int64_t)shared - (int64_t)here));
        uint64_t point = (uint64_t)(uintptr_t)&c[k - 5];

        /* 就地覆盖 guest 的 svc #0x80：b <该点桩> */
        uint32_t b = aos_emit_b((int32_t)((int64_t)point - (int64_t)svc_addr));
        uintptr_t pg = (uintptr_t)svc_addr & ~(uintptr_t)(page - 1);
        if (mprotect((void *)pg, page, PROT_READ | PROT_WRITE) != 0)
            return AOS_ERR_IO;
        aos_wr32((void *)(uintptr_t)svc_addr, b);
        if (mprotect((void *)pg, page, PROT_READ | PROT_EXEC) != 0)
            return AOS_ERR_IO;
        aos_jit_flush_icache((void *)(uintptr_t)svc_addr,
                             (void *)(uintptr_t)(svc_addr + 4));
        patched++;
    }

    ex->stub_used = k * sizeof(uint32_t);
    if (mprotect(ex->stub_base, ex->stub_size, PROT_READ | PROT_EXEC) != 0)
        return AOS_ERR_IO;
    aos_jit_flush_icache(ex->stub_base,
                         (uint8_t *)ex->stub_base + ex->stub_used);
    ex->patched_count = patched;
    if (out_patched) *out_patched = patched;
    AOS_LOG_INFO("ABI 边界预补丁完成：%zu 个 svc #0x80 已改为 b <JIT 跳板>"
                 "（guest 其余机器码保持原样、硬件原生执行）", patched);
    return AOS_OK;
}

/* ---------- 宿主 C 陷阱分派器（真转发 Linux syscall） ---------- */
int64_t aos_trap_dispatch(int64_t nr, uint64_t args[6]) {
    g_trap_count++;
    int64_t norm = (nr < 0) ? nr : (int64_t)((uint64_t)nr & 0x00FFFFFFu);

#ifdef __ANDROID__
    /* Android App 的 stdout 默认不可见：把 guest 的 write(1/2, ...) 旁路到
     * logcat（tag = A-OS-GUEST）。Linux syscall 仍然照常真转发，guest 语义不变。 */
    if (norm == 4 && (args[0] == 1 || args[0] == 2) &&
        args[1] != 0 && args[2] > 0 && args[2] < 4096) {
        char line[4096];
        size_t n = (size_t)args[2];
        memcpy(line, (const void *)(uintptr_t)args[1], n);
        line[n] = '\0';
        __android_log_print(ANDROID_LOG_INFO, "A-OS-GUEST", "%s", line);
    }
#endif

    /* XNU exit(1)：绝不能真把宿主进程干掉，longjmp 回 aos_exec_run */
    if (norm == 1) {
        if (g_exit_jmp) longjmp(*g_exit_jmp, (int)((args[0] & 0xFFu) + 1));
        return 0;
    }

    uint32_t flags = 0;
    int32_t linux_nr = aos_syscall_translate(nr, args, &flags);
    if (linux_nr >= 0) {
        errno = 0;
        return (int64_t)syscall((long)linux_nr,
                               (long)args[0], (long)args[1], (long)args[2],
                               (long)args[3], (long)args[4], (long)args[5]);
    }
    if (flags & AOS_MAP_EMULATE) {   /* Mach trap：无 Linux 等价物，用户态伪实现 */
        switch (nr) {
            case -26: return 0x0A07;  /* mach_reply_port 伪端口 */
            case -27: return 0x0A08;  /* thread_self */
            case -28: return 0x0A05;  /* task_self */
            case -29: return 0x0A06;  /* host_self */
            case -31: case -32: return 0; /* MACH_MSG_SUCCESS */
            default:  return 1;
        }
    }
    return -38;   /* -ENOSYS */
}

uint64_t aos_trap_count(void) { return g_trap_count; }

/* ---------- 真正跳进 guest（仅 aarch64） ---------- */
int aos_exec_run(aos_exec_t *ex) {
    if (!ex || !ex->entry) return AOS_ERR_INVALID_ARG;
#if defined(__aarch64__)
    jmp_buf jb;
    int rc = setjmp(jb);
    if (rc != 0) {                 /* guest 触发了 XNU exit */
        g_exit_jmp = NULL;
        return rc - 1;
    }
    g_exit_jmp = &jb;
    void (*volatile fn)(void) = (void (*)(void))(uintptr_t)ex->entry;
    fn();                          /* blr 到 guest 入口；此后硬件原生执行 */
    g_exit_jmp = NULL;
    return AOS_ERR_BAD_FORMAT;     /* guest 没走 exit 却返回了，异常 */
#else
    return AOS_ERR_UNSUPPORTED;    /* x86_64 / CI：只编译不执行 */
#endif
}

/* ---------- 内置真实 arm64 guest 样本 ----------
 * 机器码由 clang --target=aarch64-linux-gnu 汇编 guest.S 后 readelf 提取，
 * 反汇编核对：
 *   +00 mov x0,#1      +04 adr x1,0x24   +08 mov x2,#15    +0C mov x16,#4
 *   +10 svc #0x80      +14 mov x0,#42    +18 mov x16,#1    +1C svc #0x80
 *   +20 b .            +24 "A-OS NATIVE OK\n\0"
 * 全 PC 相对、位置无关，不需要任何 rebase / bind。 */
static const uint32_t kGuestCode[] = {
    0xD2800020u, 0x10000101u, 0xD28001E2u, 0xD2800090u,
    0xD4001001u, 0xD2800540u, 0xD2800030u, 0xD4001001u,
    0x14000000u, 0x534F2D41u, 0x54414E20u, 0x20455649u,
    0x000A4B4Fu
};

/* 第二套样本：write 的返回值（15）必须被写回 guest 的 x0，
 * guest 再把它当 exit 码传出 —— 验证「转译结果回写」这条闭环。
 *   +00 mov x0,#1   +04 adr x1,0x20   +08 mov x2,#15   +0C mov x16,#4
 *   +10 svc #0x80   +14 mov x16,#1    +18 svc #0x80    +1C b .
 *   +20 "A-OS NATIVE OK\n\0" */
static const uint32_t kGuestCodeRet[] = {
    0xD2800020u, 0x100000E1u, 0xD28001E2u, 0xD2800090u,
    0xD4001001u, 0xD2800030u, 0xD4001001u, 0x14000000u,
    0x534F2D41u, 0x54414E20u, 0x20455649u, 0x000A4B4Fu
};

static int build_with_code(uint8_t **out_buf, size_t *out_len,
                           const uint32_t *code, size_t code_bytes) {
    if (!out_buf || !out_len) return AOS_ERR_INVALID_ARG;
    size_t len = 0x2000u;
    uint8_t *b = (uint8_t *)aos_alloc(len);
    if (!b) return AOS_ERR_NO_MEM;

    aos_wr32(b + 0,  AOS_MH_MAGIC_64);
    aos_wr32(b + 4,  AOS_CPU_TYPE_ARM64);
    aos_wr32(b + 8,  AOS_CPU_SUBTYPE_ARM64_ALL);
    aos_wr32(b + 12, AOS_MH_EXECUTE);
    aos_wr32(b + 16, 2u);
    aos_wr32(b + 20, AOS_SIZEOF_SEGMENT_COMMAND_64 + AOS_SIZEOF_SECTION_64
                     + AOS_SIZEOF_ENTRY_POINT_COMMAND);
    aos_wr32(b + 24, 0u);
    aos_wr32(b + 28, 0u);

    uint8_t *seg = b + AOS_SIZEOF_MACH_HEADER_64;
    aos_wr32(seg + 0, AOS_LC_SEGMENT_64);
    aos_wr32(seg + 4, AOS_SIZEOF_SEGMENT_COMMAND_64 + AOS_SIZEOF_SECTION_64);
    memcpy(seg + 8, "__TEXT", 7);
    aos_wr64(seg + 24, 0x100000000ULL);
    aos_wr64(seg + 32, 0x2000ULL);
    aos_wr64(seg + 40, 0ULL);
    aos_wr64(seg + 48, 0x2000ULL);
    aos_wr32(seg + 56, 7u);
    aos_wr32(seg + 60, 5u);   /* initprot = R-X */
    aos_wr32(seg + 64, 1u);
    aos_wr32(seg + 68, 0u);

    uint8_t *sec = seg + AOS_SIZEOF_SEGMENT_COMMAND_64;
    memcpy(sec + 0, "__text", 7);
    memcpy(sec + 16, "__TEXT", 7);
    aos_wr64(sec + 32, 0x100001000ULL);
    aos_wr64(sec + 40, code_bytes);
    aos_wr32(sec + 48, 0x1000u);
    aos_wr32(sec + 52, 4u);
    aos_wr32(sec + 64, 0x80000000u); /* S_ATTR_PURE_INSTRUCTIONS */

    uint8_t *mn = b + AOS_SIZEOF_MACH_HEADER_64
                    + AOS_SIZEOF_SEGMENT_COMMAND_64 + AOS_SIZEOF_SECTION_64;
    aos_wr32(mn + 0, AOS_LC_MAIN);
    aos_wr32(mn + 4, AOS_SIZEOF_ENTRY_POINT_COMMAND);
    aos_wr64(mn + 8, 0x1000ULL);
    aos_wr64(mn + 16, 0ULL);

    memcpy(b + 0x1000, code, code_bytes);
    *out_buf = b; *out_len = len;
    return AOS_OK;
}

int aos_guest_build_sample(uint8_t **out_buf, size_t *out_len) {
    return build_with_code(out_buf, out_len, kGuestCode, sizeof(kGuestCode));
}

int aos_guest_build_sample_ret(uint8_t **out_buf, size_t *out_len) {
    return build_with_code(out_buf, out_len, kGuestCodeRet, sizeof(kGuestCodeRet));
}
