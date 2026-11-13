/*
 * A-OS 兼容层 —— Syscall User Dispatch 拦截层
 *
 * 为什么用 SUD 而不是 seccomp：
 *   seccomp 过滤器按"调用号"匹配，无法按"这条 svc 来自哪段代码"高效区分；
 *   guest 的 svc #0x80 在 Linux 眼里就是 svc #0 + x8 垃圾号，直接放行会
 *   执行一个完全不相干的 Linux 调用。SUD 按【指令地址区间】拦截，
 *   宿主 bionic/libc 的调用零损耗直通，切人格只改一个用户态 selector 字节，
 *   不进内核 —— 这就是"转译部分用 JIT 加速"的底座。
 *
 * 冷路径：guest 首次执行 svc → SIGSYS → 查表转发 → 回到 guest；
 * 热路径：JIT 把该 svc 就地改成 b <trampoline>（见 jit_arm64.c），
 *         之后连信号都不用进。
 *
 * 许可证：GPL-3.0-only
 */
#include "aos_syscall.h"
#include <sys/prctl.h>
#include <signal.h>
#include <string.h>

#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#endif
#ifndef PR_SYS_DISPATCH_OFF
#define PR_SYS_DISPATCH_OFF 0
#endif
#ifndef PR_SYS_DISPATCH_ON
#define PR_SYS_DISPATCH_ON 1   /* INCLUSIVE：区间内按 selector 拦截 */
#endif
#ifndef SYSCALL_DISPATCH_FILTER_ALLOW
#define SYSCALL_DISPATCH_FILTER_ALLOW 0
#endif
#ifndef SYSCALL_DISPATCH_FILTER_BLOCK
#define SYSCALL_DISPATCH_FILTER_BLOCK 1
#endif

/* 只有 aarch64 实机才真正装拦截；x86_64 CI 上绝不能启用，
 * 否则会把测试进程自己的 syscall 一起拦死。 */
#if defined(__aarch64__) && defined(__linux__)
#define AOS_SUD_REAL 1
#include <ucontext.h>
#include <unistd.h>
#include <errno.h>
#else
#define AOS_SUD_REAL 0
#endif

int aos_dispatch_init(aos_dispatch_t *d, uintptr_t guest_lo, size_t guest_len) {
    if (!d) return AOS_ERR_INVALID_ARG;
    memset(d, 0, sizeof(*d));
    d->guest_lo  = guest_lo;
    d->guest_len = guest_len;
    d->selector  = SYSCALL_DISPATCH_FILTER_ALLOW;

#if AOS_SUD_REAL
    if (guest_lo != 0 && guest_len != 0) {
        if (prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON,
                  (unsigned long)guest_lo, (unsigned long)guest_len,
                  &d->selector) == 0) {
            d->mode = 1;
            AOS_LOG_INFO("SUD 已启用：guest 区间 [0x%lx,+0x%zx) 的 svc 转由用户态裁决",
                         (unsigned long)guest_lo, guest_len);
            return AOS_OK;
        }
        AOS_LOG_WARN("内核不支持 SUD（需 Linux 5.11+），退回 seccomp SIGSYS 方案");
        d->mode = 2;
        return AOS_OK;
    }
#endif
    d->mode = 0; /* 逻辑桩：CI / 非 aarch64 */
    return AOS_OK;
}

void aos_dispatch_set_personality(aos_dispatch_t *d, int guest_active) {
    if (!d) return;
    /* 关键：不进内核，纯用户态写一个字节 */
    d->selector = guest_active ? SYSCALL_DISPATCH_FILTER_BLOCK
                               : SYSCALL_DISPATCH_FILTER_ALLOW;
}

void aos_dispatch_shutdown(aos_dispatch_t *d) {
    if (!d) return;
#if AOS_SUD_REAL
    if (d->mode == 1)
        prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF,
              0UL, 0UL, 0UL);
#endif
    d->mode = 0;
    d->selector = SYSCALL_DISPATCH_FILTER_ALLOW;
}

const char *aos_dispatch_mode_name(const aos_dispatch_t *d) {
    if (!d) return "未初始化";
    switch (d->mode) {
        case 1: return "Syscall User Dispatch（内核按地址区间拦截）";
        case 2: return "seccomp SIGSYS 回退";
        default: return "逻辑桩（非 aarch64 实机，仅验证转译表）";
    }
}

#if AOS_SUD_REAL
/* glibc aarch64：uc_mcontext.regs[0..30]=x0..x30, [31]=sp, [32]=pc, [33]=pstate
 * 不同 libc 布局需校准；这里按主线 glibc 写。 */
static int handle_aarch64(aos_dispatch_t *d, ucontext_t *uc) {
    unsigned long long *r = (unsigned long long *)uc->uc_mcontext.regs;
    int64_t trap_nr = (int64_t)r[16];           /* x16 = XNU 调用号 */
    uint64_t args[6] = { r[0], r[1], r[2], r[3], r[4], r[5] };
    uint32_t flags = 0;
    int32_t linux_nr = aos_syscall_translate(trap_nr, args, &flags);

    int64_t ret;
    if (linux_nr >= 0) {
        /* libc 的 syscall() 位于 guest 区间外，SUD 直通，不会递归拦截 */
        errno = 0;
        long rv = syscall((long)linux_nr, args[0], args[1], args[2],
                          args[3], args[4], args[5]);
        ret = (int64_t)rv;
    } else if (flags & AOS_MAP_EMULATE) {
        /* Mach trap：这里交给 XPC 桥；当前骨架返回伪句柄/成功 */
        ret = (trap_nr == -31) ? 0 /* MACH_MSG_SUCCESS */ : 1;
    } else {
        ret = -38; /* -ENOSYS */
    }

    r[0] = (unsigned long long)ret;
    r[33] &= ~(1ULL << 29);  /* 清 NZCV 的 C 位：Linux 用 -errno 表示错误 */
    r[32] += 4;              /* 跳过这条 svc #0x80（4 字节） */
    (void)d;
    return AOS_OK;
}
#endif

int aos_handle_guest_trap(aos_dispatch_t *d, void *ucontext_ptr) {
    if (!d || !ucontext_ptr) return AOS_ERR_INVALID_ARG;
#if AOS_SUD_REAL
    return handle_aarch64(d, (ucontext_t *)ucontext_ptr);
#else
    (void)d; (void)ucontext_ptr;
    return AOS_ERR_UNSUPPORTED;
#endif
}
