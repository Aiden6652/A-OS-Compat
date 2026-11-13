/*
 * A-OS 兼容层 —— ARM64 JIT 指令发射器单元测试
 *
 * 全部期望字节来自：
 *   clang --target=aarch64-linux-gnu -c enc_ref.S && readelf -x .text
 * 反汇编核对，不是手写的猜测常量。
 * 注意：x86_64 宿主上只验证【发射出的字节】，绝不调用这些 aarch64 机器码。
 * 许可证：GPL-3.0-only
 */
#include "test_util.h"
#include "aos_jit.h"
#include <string.h>

int main(void) {
    /* ---- 单条指令编码 ---- */
    T_CHECK(aos_emit_movz(16, 4, 0) == 0xD2800090u, "movz x16,#4 = 0xD2800090");
    T_CHECK(aos_emit_movk(16, 0x1234, 1) == 0xF2A24690u,
            "movk x16,#0x1234,lsl#16 = 0xF2A24690");
    T_CHECK(aos_emit_br(16) == 0xD61F0200u, "br x16 = 0xD61F0200");
    T_CHECK(aos_emit_blr(16) == 0xD63F0200u, "blr x16 = 0xD63F0200");
    T_CHECK(aos_emit_svc(0x80) == AOS_A64_SVC_80, "svc #0x80 编码与常量一致");
    T_CHECK(aos_emit_svc(0) == AOS_A64_SVC_0, "svc #0 编码与常量一致");
    T_CHECK(AOS_A64_RET == 0xD65F03C0u, "ret = 0xD65F03C0");
    T_CHECK(AOS_A64_NOP == 0xD503201Fu, "nop = 0xD503201F");
    T_CHECK(AOS_A64_BRK_0 == 0xD4200000u, "brk #0 = 0xD4200000");
    T_CHECK(aos_emit_orr_reg(2, 31, 1) == 0xAA0103E2u, "mov x2,x1 = 0xAA0103E2");
    T_CHECK(aos_emit_add_imm(16, 16, 4) == 0x91001210u, "add x16,x16,#4 = 0x91001210");
    T_CHECK(aos_emit_b(8) == 0x14000002u, "b .+8 = 0x14000002");
    T_CHECK(aos_emit_bl(8) == 0x94000002u, "bl .+8 = 0x94000002");
    T_CHECK(aos_jit_patch_svc_to_b(8) == 0x14000002u, "svc→b 热补丁复用 b 编码");

    aos_jit_buf_t b;
    T_CHECK(aos_jit_init(&b, 32) == AOS_OK, "JIT 缓冲初始化");

    /* ---- 64 位立即数装载 ---- */
    T_CHECK(aos_jit_mov64(&b, 16, 0x1122334455667788ULL) == AOS_OK, "mov64 发射成功");
    T_CHECK(b.len == 4, "mov64 = movz + 3×movk，共 4 条");
    T_CHECK(b.code[0] == aos_emit_movz(16, 0x7788, 0), "mov64 第 0 段（低 16 位）");
    T_CHECK(b.code[1] == aos_emit_movk(16, 0x5566, 1), "mov64 第 1 段");
    T_CHECK(b.code[2] == aos_emit_movk(16, 0x3344, 2), "mov64 第 2 段");
    T_CHECK(b.code[3] == aos_emit_movk(16, 0x1122, 3), "mov64 第 3 段（高 16 位）");

    /* ---- 转译加速核心：绝对跳转 trampoline ---- */
    aos_jit_reset(&b);
    T_CHECK(aos_jit_emit_abs_jump(&b, 0x1122334455667788ULL, 16) == AOS_OK,
            "绝对跳转 trampoline 发射成功");
    T_CHECK(b.len == 5, "trampoline 共 5 条（4 装载 + br）");
    T_CHECK(b.code[4] == aos_emit_br(16), "trampoline 以 br scratch 结尾");
    T_CHECK(aos_jit_emit_abs_jump(&b, 0, 31) == AOS_ERR_INVALID_ARG,
            "scratch 寄存器 > 30 被拒绝");

    /* ---- XNU 调用桩（冷路径回放参考） ---- */
    aos_jit_reset(&b);
    T_CHECK(aos_jit_emit_xnu_call_stub(&b, -31) == AOS_OK, "XNU 调用桩发射成功");
    T_CHECK(b.len == 6, "XNU 桩 = 4 装载 + svc + ret = 6 条");
    T_CHECK(b.code[4] == AOS_A64_SVC_80, "XNU 桩第 5 条为 svc #0x80");
    T_CHECK(b.code[5] == AOS_A64_RET, "XNU 桩以 ret 结尾");
    T_CHECK(b.code[0] == aos_emit_movz(16, 0xFFE1, 0),
            "Mach trap -31 的 64 位补码低 16 位 = 0xFFE1");

    /* ---- 原函数重定位跳板（对应 ElleKit 的 orig） ---- */
    aos_jit_reset(&b);
    int n = aos_jit_emit_orig_trampoline(&b, 0x1000ULL, AOS_A64_NOP);
    T_CHECK(n == 6, "orig 跳板共 6 条");
    T_CHECK(b.code[0] == aos_emit_movz(16, 0x1004, 0),
            "跳回地址 = target+4（跳过被覆盖的 1 条指令）");
    T_CHECK(b.code[4] == AOS_A64_NOP, "orig 跳板就地重放被覆盖的原指令");
    T_CHECK(b.code[5] == aos_emit_br(16), "orig 跳板以 br x16 跳回");

    /* ---- W^X 可执行页：只验字节，不执行 ---- */
    aos_jit_reset(&b);
    aos_jit_put(&b, AOS_A64_NOP);
    aos_jit_put(&b, AOS_A64_RET);
    void *exec = aos_jit_seal(&b);
    T_CHECK(exec != NULL, "seal 成功映射可执行页（RW → RX）");
    if (exec) {
        T_CHECK(b.exec_size > 0, "seal 记录了映射大小");
        T_CHECK(memcmp(exec, b.code, b.len * sizeof(uint32_t)) == 0,
                "可执行页内容与发射缓冲逐字节一致");
        aos_jit_unmap(&b);
        T_CHECK(b.exec_mem == NULL, "unmap 后清空映射指针");
    }
    aos_jit_flush_icache(b.code, b.code + b.len); /* 非 aarch64 为空操作 */

    /* ---- 容量边界 ---- */
    aos_jit_destroy(&b);
    T_CHECK(aos_jit_init(&b, 2) == AOS_OK, "小容量缓冲初始化");
    T_CHECK(aos_jit_put(&b, AOS_A64_NOP) == AOS_OK, "第 1 条写入成功");
    T_CHECK(aos_jit_put(&b, AOS_A64_NOP) == AOS_OK, "第 2 条写入成功");
    T_CHECK(aos_jit_put(&b, AOS_A64_NOP) == AOS_ERR_NO_SPACE, "超出容量 → NO_SPACE");
    aos_jit_destroy(&b);
    T_CHECK(b.code == NULL && b.cap == 0, "destroy 后缓冲归零");

    T_REPORT("test_jit");
}
