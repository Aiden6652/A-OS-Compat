/*
 * A-OS 兼容层 —— ARM64 JIT 指令发射器
 *
 * 用途边界（总架构师定调）：
 *   · IPA 自身的 arm64 机器码【不转译、不模拟】，由硬件原生执行；
 *   · JIT 只用于【转译部分】的加速：把 XNU ABI 边界（svc #0x80 / Mach trap /
 *     ObjC 消息桥 / 高频框架调用）在运行时编译成宿主可直接跳的 trampoline，
 *     避免每次都掉进 SIGSYS/seccomp 慢路径。
 *   · 普通 arm64 应用无 PAC，因此跳板里不需要 PACIASP/AUTIASP 签名，
 *     4 字节 b/br 直接覆盖即可（这是本方案最大的便宜）。
 *
 * 所有编码均由 clang --target=aarch64-linux-gnu 反汇编核对过。
 * 许可证：GPL-3.0-only
 */
#ifndef AOS_JIT_H
#define AOS_JIT_H

#include "aos_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 已核对的 ARM64 硬编码 ---- */
#define AOS_A64_RET          0xD65F03C0u  /* ret                 */
#define AOS_A64_NOP          0xD503201Fu  /* nop                 */
#define AOS_A64_SVC_80       0xD4001001u  /* svc #0x80（XNU）    */
#define AOS_A64_SVC_0        0xD4000001u  /* svc #0（Linux）     */
#define AOS_A64_BRK_0        0xD4200000u  /* brk #0（陷阱）      */

typedef struct {
    uint32_t *code;        /* 指令字数组 */
    size_t     cap;        /* 容量（指令数） */
    size_t     len;        /* 已发射指令数 */
    void      *exec_mem;   /* seal 后的可执行页 */
    size_t     exec_size;
} aos_jit_buf_t;

int  aos_jit_init(aos_jit_buf_t *b, size_t cap_insns);
void aos_jit_destroy(aos_jit_buf_t *b);
void aos_jit_reset(aos_jit_buf_t *b);

/* 单条指令发射，成功返回 AOS_OK，缓冲区满返回 AOS_ERR_NO_SPACE */
int aos_jit_put(aos_jit_buf_t *b, uint32_t insn);

uint32_t aos_emit_movz(unsigned rd, uint16_t imm, unsigned hw);
uint32_t aos_emit_movk(unsigned rd, uint16_t imm, unsigned hw);
uint32_t aos_emit_br(unsigned rn);
uint32_t aos_emit_blr(unsigned rn);
uint32_t aos_emit_b(int32_t byte_offset);       /* ±128MB */
uint32_t aos_emit_bl(int32_t byte_offset);
uint32_t aos_emit_svc(uint16_t imm);
uint32_t aos_emit_add_imm(unsigned rd, unsigned rn, uint16_t imm);
uint32_t aos_emit_orr_reg(unsigned rd, unsigned rn, unsigned rm); /* mov rd, rm */

/* 把 64 位立即数装进寄存器：movz + 3×movk */
int aos_jit_mov64(aos_jit_buf_t *b, unsigned rd, uint64_t value);

/* 【转译加速核心】生成一段"绝对跳转"trampoline：
 *   movz/movk 装载 target → br reg
 * 共 5 条指令。用于把 guest 的 svc #0x80 热补丁成直接跳到宿主实现。 */
int aos_jit_emit_abs_jump(aos_jit_buf_t *b, uint64_t target, unsigned scratch_reg);

/* 生成 XNU syscall 桩：把 Darwin 调用号装进 x16 后 svc #0x80，ret。
 * 这是冷路径回放用的参考桩（宿主自己仍是 Linux svc #0）。 */
int aos_jit_emit_xnu_call_stub(aos_jit_buf_t *b, int64_t trap_nr);

/* 生成"重定位原函数"跳板（对应 ElleKit 的 orig 汇编）：
 *   mov64 x16, target+4 ; 执行被覆盖的原 1 条指令 ; br x16
 * 返回写出的指令数。original_insn 是被 b 覆盖掉的那 4 字节。 */
int aos_jit_emit_orig_trampoline(aos_jit_buf_t *b, uint64_t target,
                                 uint32_t original_insn);

/* 冷→热升级：把 guest 代码页里的 svc #0x80 就地改成 b <jit_stub>。
 * 返回写入的指令字；调用方负责 mprotect + __clear_cache。 */
uint32_t aos_jit_patch_svc_to_b(int32_t byte_offset);

/* 刷新指令缓存（aarch64 实机有效，其他平台为空操作） */
void aos_jit_flush_icache(void *start, void *end);

/* 把代码缓冲区映射成可执行页（W^X），返回可用函数地址；失败返回 NULL */
void *aos_jit_seal(aos_jit_buf_t *b);
void  aos_jit_unmap(aos_jit_buf_t *b);

#ifdef __cplusplus
}
#endif
#endif /* AOS_JIT_H */
