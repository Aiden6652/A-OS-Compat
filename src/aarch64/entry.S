/*
 * A-OS 兼容层 —— ARM64 上下文切换跳板
 *
 * 职责：保存宿主现场 → 切到 guest 栈 → 直接 br 到 IPA 的入口。
 * 【IPA 自身的 arm64 机器码全程原生执行，没有翻译、没有解释、没有 QEMU。】
 * 需要转译的只有 XNU ABI 边界：guest 的 svc #0x80 由 SUD 拦成 SIGSYS，
 * 宿主裁决后回到 guest；热点再由 JIT 把 svc 就地改成 b <trampoline>。
 *
 * 普通 arm64 应用无 PAC，因此这里不发射 paciasp / autiasp / braa
 * （那是 arm64e 系统库才需要的），4 字节 b/br 可直接覆盖函数序言。
 *
 * 许可证：GPL-3.0-only
 */
    .text
    .align 4

/* int aos_enter_guest(void *entry, void *guest_sp, void *host_save)
 * x0 = guest 入口  x1 = guest 栈顶  x2 = 宿主现场保存区（>= 104 字节，16 对齐）
 * 正常不返回；guest 通过陷阱回宿主后由 aos_restore_host 恢复。 */
    .globl aos_enter_guest
    .type  aos_enter_guest, %function
aos_enter_guest:
    stp  x19, x20, [x2, #0]
    stp  x21, x22, [x2, #16]
    stp  x23, x24, [x2, #32]
    stp  x25, x26, [x2, #48]
    stp  x27, x28, [x2, #64]
    stp  x29, x30, [x2, #80]
    mov  x3, sp
    str  x3, [x2, #96]
    mov  sp, x1                 /* 切到 iOS guest 栈 */
    br   x0                     /* 硬件原生执行，零指令转译 */
    .size aos_enter_guest, .-aos_enter_guest

/* void aos_restore_host(void *host_save)
 * 恢复宿主 callee-saved 与栈指针并返回调用者 */
    .globl aos_restore_host
    .type  aos_restore_host, %function
aos_restore_host:
    ldr  x3, [x0, #96]
    mov  sp, x3
    ldp  x19, x20, [x0, #0]
    ldp  x21, x22, [x0, #16]
    ldp  x23, x24, [x0, #32]
    ldp  x25, x26, [x0, #48]
    ldp  x27, x28, [x0, #64]
    ldp  x29, x30, [x0, #80]
    ret
    .size aos_restore_host, .-aos_restore_host

/* JIT 陷阱向量骨架。
 * 约定：JIT 把 guest 的 svc #0x80 改成 b 到这里；此时
 *       x16 = XNU 调用号（guest 原值）、x0..x5 = 参数、x30 = 返回地址。
 * 完整实现需在此构造 ucontext_t 并调用 C 的 aos_handle_guest_trap，
 * 再按结果写回 x0 / 清 C 位 / 返回。当前里程碑先提供可汇编的骨架向量，
 * 保证交叉编译链路可验证；逻辑分派已在 src/syscall_dispatch.c 实现。 */
    .globl aos_trap_vector
    .type  aos_trap_vector, %function
aos_trap_vector:
    sub  sp, sp, #96
    stp  x0,  x1,  [sp, #0]
    stp  x2,  x3,  [sp, #16]
    stp  x4,  x5,  [sp, #32]
    stp  x16, x30, [sp, #48]
    str  x17, [sp, #64]
    /* 此处转交 C 分派器：aos_handle_guest_trap(dispatch, ctx) */
    ldp  x0,  x1,  [sp, #0]
    ldp  x2,  x3,  [sp, #16]
    ldp  x4,  x5,  [sp, #32]
    ldp  x16, x30, [sp, #48]
    ldr  x17, [sp, #64]
    add  sp, sp, #96
    ret
    .size aos_trap_vector, .-aos_trap_vector

/* 读取虚拟计数器：宿主侧用于评估冷/热路径开销，决定是否升级为 JIT 桩 */
    .globl aos_read_cntvct
    .type  aos_read_cntvct, %function
aos_read_cntvct:
    mrs  x0, cntvct_el0
    ret
    .size aos_read_cntvct, .-aos_read_cntvct

    .section .note.GNU-stack,"",%progbits
