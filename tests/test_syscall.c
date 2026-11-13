/*
 * A-OS 兼容层 —— XNU/Darwin syscall 转译表与拦截层单元测试
 * 许可证：GPL-3.0-only
 */
#include "test_util.h"
#include "aos_syscall.h"
#include <string.h>

int main(void) {
    /* ---- 陷阱分类 ---- */
    T_CHECK(aos_trap_classify(-31) == AOS_TRAP_MACH, "负号 → Mach trap");
    T_CHECK(aos_trap_classify(3) == AOS_TRAP_BSD, "裸正号 → BSD");
    T_CHECK(aos_trap_classify(0x02000003) == AOS_TRAP_BSD, "class=2(UNIX) → BSD");
    T_CHECK(aos_trap_classify(0x0100001F) == AOS_TRAP_MACH, "class=1(MACH) → Mach");
    T_CHECK(aos_trap_classify(0x03000001) == AOS_TRAP_MDEP, "class=3 → MDEP");
    T_CHECK(aos_trap_classify(0x04000001) == AOS_TRAP_UNKNOWN, "未知 class");

    /* ---- 转译表 ---- */
    T_CHECK(aos_syscall_table_size() == 40, "转译表共 40 条（34 BSD + 6 Mach trap）");
    const aos_syscall_map_t *m = aos_syscall_lookup(3);
    T_CHECK(m && !strcmp(m->xnu_name, "read") && m->linux_nr == 63,
            "XNU read(3) → Linux read(63)");
    m = aos_syscall_lookup(0x02000005);
    T_CHECK(m && !strcmp(m->xnu_name, "open") && (m->flags & AOS_MAP_ARG_REWRITE),
            "带 class 前缀的 open 号归一化后命中 ARG_REWRITE");
    m = aos_syscall_lookup(-31);
    T_CHECK(m && !strcmp(m->xnu_name, "mach_msg") && (m->flags & AOS_MAP_EMULATE),
            "mach_msg 无 Linux 等价物 → 用户态模拟");
    T_CHECK(aos_syscall_lookup(9999) == NULL, "未收录号返回 NULL");

    /* ---- 参数转译 ---- */
    uint64_t a[6] = {1, 2, 3, 4, 5, 6};
    uint32_t fl = 0;
    T_CHECK(aos_syscall_translate(3, a, &fl) == 63, "read 直接转发到 63");
    T_CHECK((fl & AOS_MAP_DIRECT) && a[0] == 1 && a[5] == 6,
            "DIRECT 调用不改写任何参数寄存器");

    uint64_t o[6] = {0x1000, 0x2, 0x1B6, 0, 0, 0};
    T_CHECK(aos_syscall_translate(5, o, &fl) == 56, "open → Linux openat(56)");
    T_CHECK((fl & AOS_MAP_ARG_REWRITE) &&
            o[0] == (uint64_t)-100 && o[1] == 0x1000 &&
            o[2] == 0x2 && o[3] == 0x1B6,
            "open 参数重写：补 AT_FDCWD(-100)，path/flags/mode 依次右移");

    uint64_t u[6] = {0x2000, 0, 0, 0, 0, 0};
    T_CHECK(aos_syscall_translate(10, u, &fl) == 35, "unlink → unlinkat(35)");
    T_CHECK(u[0] == (uint64_t)-100 && u[1] == 0x2000 && u[2] == 0,
            "unlink 参数重写：补 AT_FDCWD 与 dirfd 标志 0");

    uint64_t z[6] = {0};
    T_CHECK(aos_syscall_translate(-31, z, &fl) == -1 && (fl & AOS_MAP_EMULATE),
            "Mach trap 交给用户态 XPC 桥模拟");
    T_CHECK(aos_syscall_translate(26, z, &fl) == -1 && (fl & AOS_MAP_UNSUPPORTED),
            "ptrace 明确拒绝（UNSUPPORTED）");
    T_CHECK(aos_syscall_translate(9999, z, &fl) == -1 && (fl & AOS_MAP_UNSUPPORTED),
            "未收录号返回 ENOSYS 语义");

    /* ---- 错误约定转换 ---- */
    T_CHECK(aos_xnu_to_linux_ret(13, 1) == -13,
            "XNU carry 置位：x0=errno 13 → Linux -13");
    T_CHECK(aos_xnu_to_linux_ret(42, 0) == 42, "成功返回值原样透传");

    /* ---- Syscall User Dispatch（非 aarch64 上为逻辑桩） ---- */
    aos_dispatch_t d;
    T_CHECK(aos_dispatch_init(&d, 0, 0) == AOS_OK, "dispatch 初始化");
    T_CHECK(d.guest_lo == 0 && d.guest_len == 0, "guest 区间已记录");
    unsigned char s0 = d.selector;
    aos_dispatch_set_personality(&d, 1);
    T_CHECK(d.selector != s0, "切人格只改一个用户态 selector 字节（不进内核）");
    aos_dispatch_set_personality(&d, 0);
    T_CHECK(d.selector == s0, "切回宿主人格恢复 ALLOW");
    T_CHECK(strstr(aos_dispatch_mode_name(&d), "桩") != NULL,
            "x86_64 / CI 上退化为逻辑桩，不误拦宿主 syscall");
    aos_dispatch_shutdown(&d);
    T_CHECK(d.mode == 0, "shutdown 后回到未启用");
    T_CHECK(aos_handle_guest_trap(&d, &d) == AOS_ERR_UNSUPPORTED,
            "非 aarch64 上陷阱处理器明确返回不支持");

    T_REPORT("test_syscall");
}
