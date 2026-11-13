/*
 * A-OS 兼容层 —— 宿主陷阱桩（aarch64 专用）
 *
 * 由 JIT 生成的每点专属跳板把控制权交给这里：
 *   x9  = guest 返回地址（被覆盖的 svc 指令 + 4）
 *   x16 = XNU 调用号（guest 原值）
 *   x0..x5 = 参数
 *   x30 保持 guest 原值（跳板用 b 而不是 bl，绝不碰 lr）
 *
 * 流程：保存现场 → 调 C 分派器真转发 Linux syscall →
 *       Linux「-errno」转回 XNU「x0=errno + carry 置位」→
 *       恢复现场 → mov x0, 结果 → br x9 回 guest 继续执行。
 *
 * 只有 ABI 边界是转译的；guest 的其它 arm64 指令全程硬件原生执行。
 * 许可证：GPL-3.0-only
 */
    .text
    .align 4
    .globl aos_guest_trap_handler
    .type  aos_guest_trap_handler, %function
aos_guest_trap_handler:
    /* 112 字节栈帧：x0..x5(48) + x9/x16(16) + x29/x30(16) + nzcv(8) + 结果(8) */
    sub  sp, sp, #112
    stp  x0,  x1,  [sp, #0]
    stp  x2,  x3,  [sp, #16]
    stp  x4,  x5,  [sp, #32]
    stp  x9,  x16, [sp, #48]
    stp  x29, x30, [sp, #64]
    mrs  x10, nzcv
    str  x10, [sp, #80]

    mov  x0, x16                 /* arg0 = XNU 调用号 */
    mov  x1, sp                  /* arg1 = &args[0]（即保存的 x0..x5） */
    bl   aos_trap_dispatch       /* 返回 x0 = Linux 约定结果 */

    /* 错误约定转换：保留 guest 的 NZV，C 位由本次结果决定 */
    ldr  x11, [sp, #80]
    bic  x11, x11, #(1 << 29)
    cmp  x0, #0
    b.ge 1f
    neg  x0, x0                  /* -errno → errno */
    orr  x11, x11, #(1 << 29)   /* 错误：置 carry */
1:
    msr  nzcv, x11
    str  x0, [sp, #88]           /* 暂存结果，避免被下面的恢复覆盖 */

    /* 恢复 guest 现场（这些指令均不修改 NZCV） */
    ldp  x2,  x3,  [sp, #16]
    ldp  x4,  x5,  [sp, #32]
    ldp  x9,  x16, [sp, #48]
    ldp  x29, x30, [sp, #64]
    ldp  x0,  x1,  [sp, #0]
    ldr  x10, [sp, #88]
    add  sp, sp, #112
    mov  x0, x10                 /* 写回返回值 */
    br   x9                      /* 回 guest 的下一条指令，硬件原生继续跑 */
    .size aos_guest_trap_handler, .-aos_guest_trap_handler

    .section .note.GNU-stack,"",%progbits
