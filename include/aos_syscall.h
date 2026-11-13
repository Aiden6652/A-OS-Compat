/*
 * A-OS 兼容层 —— XNU/Darwin syscall ABI 转译表
 *
 * 差异（军师查实）：
 *   XNU arm64 : 调用号在 x16，svc #0x80，错误走 carry flag + x0=errno
 *   Linux arm64: 调用号在 x8 ，svc #0   ，错误走 x0 = -errno
 *   BSD 调用号自成一套（open=5 / read=3 / write=4），Mach trap 是负数
 *   （mach_msg=-31、mach_reply_port=-26、task_self=-28、host_self=-29）。
 * 直接下发 svc #0x80 会被 Linux 内核当成 svc #0 + x8 里的垃圾号，
 * 立刻 SIGSYS 或执行一个完全不相干的调用 —— 这就是必须转译的原因。
 *
 * 许可证：GPL-3.0-only
 */
#ifndef AOS_SYSCALL_H
#define AOS_SYSCALL_H

#include "aos_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 转译标记 */
#define AOS_MAP_DIRECT       0x0001u /* 号改一下即可直接转发 */
#define AOS_MAP_ARG_REWRITE  0x0002u /* 需要重写参数（如 open→openat 加 AT_FDCWD） */
#define AOS_MAP_EMULATE      0x0004u /* 无对应 Linux 调用，需用户态模拟 */
#define AOS_MAP_UNSUPPORTED  0x0008u /* 明确不支持，返回 ENOSYS */

typedef enum {
    AOS_TRAP_BSD  = 0,  /* 正数：BSD syscall */
    AOS_TRAP_MACH = 1,  /* 负数：Mach trap */
    AOS_TRAP_MDEP = 2,  /* 0x1000000+：machine dependent */
    AOS_TRAP_UNKNOWN = 3
} aos_trap_class_t;

typedef struct {
    int64_t     xnu_nr;      /* guest 放在 x16 里的号 */
    int32_t     linux_nr;    /* 转发到宿主 svc #0 的号，<0 表示不直接转发 */
    const char *xnu_name;
    const char *linux_name;
    uint32_t    flags;
} aos_syscall_map_t;

/* 陷阱分类 */
aos_trap_class_t aos_trap_classify(int64_t xnu_nr);

/* 查表；未收录返回 NULL */
const aos_syscall_map_t *aos_syscall_lookup(int64_t xnu_nr);

/* 表长（测试与统计用） */
size_t aos_syscall_table_size(void);

/* 把 guest 的 6 个参数寄存器 + 调用号，转成宿主 Linux 调用。
 * args[0..5] 对应 x0..x5，会被就地改写；返回宿主调用号。
 * 返回值 <0 表示需要用户态模拟（flags & AOS_MAP_EMULATE）。 */
int32_t aos_syscall_translate(int64_t xnu_nr, uint64_t args[6],
                              uint32_t *out_flags);

/* XNU 错误约定 → Linux 错误约定：carry 置位时把 errno 变成 -errno */
int64_t aos_xnu_to_linux_ret(int64_t x0, int carry_set);

/* ============================================================
 * 用户态拦截：Syscall User Dispatch（PR_SET_SYSCALL_USER_DISPATCH）
 * ------------------------------------------------------------
 * 比 seccomp 更合适：只拦截"guest 代码地址区间"发出的 svc，
 * 宿主自身（bionic/libc）的调用零损耗直通，切人格只改一个用户态
 * selector 字节，不用每次进出内核。这正是 Wine 采用的机制。
 * 无权限时才退化到 seccomp SIGSYS。
 * ============================================================ */
typedef struct {
    unsigned char selector;      /* 1=BLOCK(转译) 0=ALLOW(直通) */
    uintptr_t     guest_lo;      /* guest __TEXT 区间起始 */
    size_t        guest_len;
    int           mode;          /* 0=未启用 1=SUD 2=SIGSYS 回退 */
} aos_dispatch_t;

int  aos_dispatch_init(aos_dispatch_t *d, uintptr_t guest_lo, size_t guest_len);
void aos_dispatch_set_personality(aos_dispatch_t *d, int guest_active);
void aos_dispatch_shutdown(aos_dispatch_t *d);
const char *aos_dispatch_mode_name(const aos_dispatch_t *d);

/* SIGSYS/SUD 命中后的总入口：读上下文 → 查表 → 转发/模拟 → 写回结果。
 * aarch64 实机路径读 ucontext 寄存器；x86_64 CI 下为可编译的桩。 */
int aos_handle_guest_trap(aos_dispatch_t *d, void *ucontext_ptr);

#ifdef __cplusplus
}
#endif
#endif /* AOS_SYSCALL_H */
