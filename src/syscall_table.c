/*
 * A-OS 兼容层 —— XNU → Linux syscall 转译表
 *
 * 号段说明（xnu/osfmk/mach/syscall_sw.h）：
 *   x16 高 8 位是 class：0=NONE 1=MACH 2=UNIX(BSD) 3=MDEP 4=DIAG
 *   libSystem 通常下发 0x02000000|n；手写汇编里裸写 n 也能进 BSD 表；
 *   Mach trap 常用负数（-31 = mach_msg）。
 *   我们统一 normalize 到低 24 位（Mach 保留负号），再查表。
 *
 * Linux arm64 号取自 asm-generic/unistd.h。
 * 许可证：GPL-3.0-only
 */
#include "aos_syscall.h"

#define LINUX_AT_FDCWD ((uint64_t)-100)

static const aos_syscall_map_t kTable[] = {
    /* XNU号, Linux号, XNU名, Linux名, 标记 */
    {  1,  94, "exit",     "exit_group", AOS_MAP_DIRECT },
    {  2,  -1, "fork",     "（模拟）",   AOS_MAP_EMULATE },
    {  3,  63, "read",     "read",       AOS_MAP_DIRECT },
    {  4,  64, "write",    "write",      AOS_MAP_DIRECT },
    {  5,  56, "open",     "openat",     AOS_MAP_ARG_REWRITE },
    {  6,  57, "close",    "close",      AOS_MAP_DIRECT },
    {  7, 260, "wait4",    "wait4",      AOS_MAP_DIRECT },
    { 10,  35, "unlink",   "unlinkat",   AOS_MAP_ARG_REWRITE },
    { 12,  49, "chdir",    "chdir",      AOS_MAP_DIRECT },
    { 20, 172, "getpid",   "getpid",     AOS_MAP_DIRECT },
    { 23, 146, "setuid",   "setuid",     AOS_MAP_DIRECT },
    { 24, 174, "getuid",   "getuid",     AOS_MAP_DIRECT },
    { 25, 175, "geteuid",  "geteuid",    AOS_MAP_DIRECT },
    { 26,  -1, "ptrace",   "（禁止）",   AOS_MAP_UNSUPPORTED },
    { 27, 212, "recvmsg",  "recvmsg",    AOS_MAP_DIRECT },
    { 28, 211, "sendmsg",  "sendmsg",    AOS_MAP_DIRECT },
    { 29, 207, "recvfrom", "recvfrom",   AOS_MAP_DIRECT },
    { 30, 202, "accept",   "accept",     AOS_MAP_DIRECT },
    { 31, 205, "getpeername", "getpeername", AOS_MAP_DIRECT },
    { 32, 204, "getsockname", "getsockname", AOS_MAP_DIRECT },
    { 33,  48, "access",   "faccessat",  AOS_MAP_ARG_REWRITE },
    { 36,  81, "sync",     "sync",       AOS_MAP_DIRECT },
    { 37, 129, "kill",     "kill",       AOS_MAP_DIRECT },
    { 39, 173, "getppid",  "getppid",    AOS_MAP_DIRECT },
    { 41,  23, "dup",      "dup",        AOS_MAP_DIRECT },
    { 42,  59, "pipe",     "pipe2",      AOS_MAP_ARG_REWRITE },
    { 46, 176, "getgid",   "getgid",     AOS_MAP_DIRECT },
    { 54,  29, "ioctl",    "ioctl",      AOS_MAP_DIRECT },
    { 59, 221, "execve",   "execve",     AOS_MAP_DIRECT },
    { 60, 166, "umask",    "umask",      AOS_MAP_DIRECT },
    { 61,  -1, "chroot",   "（拒绝）",   AOS_MAP_UNSUPPORTED },
    { 73, 215, "munmap",   "munmap",     AOS_MAP_DIRECT },
    { 74, 226, "mprotect", "mprotect",   AOS_MAP_DIRECT },
    { 75, 233, "madvise",  "madvise",    AOS_MAP_DIRECT },

    /* Mach traps：负数。没有 Linux 等价物，一律用户态模拟。
     * 这正说明"光转发 syscall 不够"：iOS 框架的骨架是 Mach IPC。 */
    {-26, -1, "mach_reply_port", "（伪端口）", AOS_MAP_EMULATE },
    {-27, -1, "thread_self",     "（伪线程）", AOS_MAP_EMULATE },
    {-28, -1, "task_self",       "（伪任务）", AOS_MAP_EMULATE },
    {-29, -1, "host_self",       "（伪主机）", AOS_MAP_EMULATE },
    {-31, -1, "mach_msg",        "（XPC 桥）", AOS_MAP_EMULATE },
    {-32, -1, "mach_msg_overwrite", "（XPC 桥）", AOS_MAP_EMULATE },
};

aos_trap_class_t aos_trap_classify(int64_t xnu_nr) {
    if (xnu_nr < 0) return AOS_TRAP_MACH;
    uint32_t cls = ((uint64_t)xnu_nr >> 24) & 0xFFu;
    switch (cls) {
        case 1: return AOS_TRAP_MACH;
        case 2: return AOS_TRAP_BSD;
        case 3: return AOS_TRAP_MDEP;
        case 0: return AOS_TRAP_BSD;   /* 裸号，libSystem 手写汇编常见 */
        default: return AOS_TRAP_UNKNOWN;
    }
}

/* 归一化：BSD/MDEP 取低 24 位；Mach 负数原样保留 */
static int64_t normalize(int64_t nr) {
    if (nr < 0) return nr;
    if ((((uint64_t)nr >> 24) & 0xFFu) == 1) /* MACH class → 负索引 */
        return -((int64_t)((uint64_t)nr & 0x00FFFFFFu));
    return (int64_t)((uint64_t)nr & 0x00FFFFFFu);
}

const aos_syscall_map_t *aos_syscall_lookup(int64_t xnu_nr) {
    int64_t n = normalize(xnu_nr);
    for (size_t i = 0; i < sizeof(kTable) / sizeof(kTable[0]); i++)
        if (kTable[i].xnu_nr == n) return &kTable[i];
    return NULL;
}

size_t aos_syscall_table_size(void) {
    return sizeof(kTable) / sizeof(kTable[0]);
}

int32_t aos_syscall_translate(int64_t xnu_nr, uint64_t args[6],
                              uint32_t *out_flags) {
    if (!args || !out_flags) return -1;
    const aos_syscall_map_t *m = aos_syscall_lookup(xnu_nr);
    if (!m) { *out_flags = AOS_MAP_UNSUPPORTED; return -1; }
    *out_flags = m->flags;

    if (m->flags & (AOS_MAP_EMULATE | AOS_MAP_UNSUPPORTED)) return -1;

    if (m->flags & AOS_MAP_ARG_REWRITE) {
        int64_t n = normalize(xnu_nr);
        uint64_t a0 = args[0], a1 = args[1], a2 = args[2];
        switch (n) {
            case 5:  /* open(path,flags,mode) → openat(AT_FDCWD,path,flags,mode) */
                args[0] = LINUX_AT_FDCWD; args[1] = a0;
                args[2] = a1; args[3] = a2; args[4] = 0; args[5] = 0;
                break;
            case 10: /* unlink(path) → unlinkat(AT_FDCWD,path,0) */
                args[0] = LINUX_AT_FDCWD; args[1] = a0;
                args[2] = 0; args[3] = 0; args[4] = 0; args[5] = 0;
                break;
            case 33: /* access(path,mode) → faccessat(AT_FDCWD,path,mode,0) */
                args[0] = LINUX_AT_FDCWD; args[1] = a0;
                args[2] = a1; args[3] = 0; args[4] = 0; args[5] = 0;
                break;
            case 42: /* pipe(fds) → pipe2(fds,0) */
                args[0] = a0; args[1] = 0; args[2] = 0;
                args[3] = 0; args[4] = 0; args[5] = 0;
                break;
            default: break;
        }
    }
    return m->linux_nr;
}

int64_t aos_xnu_to_linux_ret(int64_t x0, int carry_set) {
    /* XNU：carry=1 时 x0 是正 errno；Linux：直接返回 -errno */
    if (carry_set) return -(x0 > 0 ? x0 : 1);
    return x0;
}
