/*
 * A-OS 兼容层 —— ARM64 JIT 指令发射器实现
 * 每条编码都由 clang --target=aarch64-linux-gnu 反汇编核对，见 tests/test_jit.c。
 * 许可证：GPL-3.0-only
 */
#include "aos_jit.h"
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int aos_jit_init(aos_jit_buf_t *b, size_t cap_insns) {
    if (!b || cap_insns == 0) return AOS_ERR_INVALID_ARG;
    memset(b, 0, sizeof(*b));
    b->code = (uint32_t *)aos_alloc(cap_insns * sizeof(uint32_t));
    if (!b->code) return AOS_ERR_NO_MEM;
    b->cap = cap_insns;
    return AOS_OK;
}

void aos_jit_reset(aos_jit_buf_t *b) {
    if (b) b->len = 0;
}

void aos_jit_unmap(aos_jit_buf_t *b) {
    if (b && b->exec_mem && b->exec_size)
        munmap(b->exec_mem, b->exec_size);
    if (b) { b->exec_mem = NULL; b->exec_size = 0; }
}

void aos_jit_destroy(aos_jit_buf_t *b) {
    if (!b) return;
    aos_jit_unmap(b);
    aos_free(b->code);
    b->code = NULL; b->cap = 0; b->len = 0;
}

int aos_jit_put(aos_jit_buf_t *b, uint32_t insn) {
    if (!b || !b->code) return AOS_ERR_INVALID_ARG;
    if (b->len >= b->cap) return AOS_ERR_NO_SPACE;
    b->code[b->len++] = insn;
    return AOS_OK;
}

uint32_t aos_emit_movz(unsigned rd, uint16_t imm, unsigned hw) {
    return 0xD2800000u | ((hw & 3u) << 21) | ((uint32_t)imm << 5) | (rd & 31u);
}
uint32_t aos_emit_movk(unsigned rd, uint16_t imm, unsigned hw) {
    return 0xF2800000u | ((hw & 3u) << 21) | ((uint32_t)imm << 5) | (rd & 31u);
}
uint32_t aos_emit_br(unsigned rn) {
    return 0xD61F0000u | ((rn & 31u) << 5);
}
uint32_t aos_emit_blr(unsigned rn) {
    return 0xD63F0000u | ((rn & 31u) << 5);
}
uint32_t aos_emit_b(int32_t byte_offset) {
    int32_t imm26 = byte_offset >> 2;
    return 0x14000000u | ((uint32_t)imm26 & 0x03FFFFFFu);
}
uint32_t aos_emit_bl(int32_t byte_offset) {
    int32_t imm26 = byte_offset >> 2;
    return 0x94000000u | ((uint32_t)imm26 & 0x03FFFFFFu);
}
uint32_t aos_emit_svc(uint16_t imm) {
    return 0xD4000001u | ((uint32_t)imm << 5);
}
uint32_t aos_emit_add_imm(unsigned rd, unsigned rn, uint16_t imm) {
    return 0x91000000u | (((uint32_t)imm & 0xFFFu) << 10) |
           ((rn & 31u) << 5) | (rd & 31u);
}
uint32_t aos_emit_orr_reg(unsigned rd, unsigned rn, unsigned rm) {
    return 0xAA000000u | ((rm & 31u) << 16) | ((rn & 31u) << 5) | (rd & 31u);
}

int aos_jit_mov64(aos_jit_buf_t *b, unsigned rd, uint64_t value) {
    int rc;
    rc = aos_jit_put(b, aos_emit_movz(rd, (uint16_t)(value & 0xFFFFu), 0));
    if (rc) return rc;
    for (unsigned hw = 1; hw < 4; hw++) {
        rc = aos_jit_put(b, aos_emit_movk(rd,
                         (uint16_t)((value >> (16 * hw)) & 0xFFFFu), hw));
        if (rc) return rc;
    }
    return AOS_OK;
}

int aos_jit_emit_abs_jump(aos_jit_buf_t *b, uint64_t target, unsigned scratch_reg) {
    if (!b || scratch_reg > 30) return AOS_ERR_INVALID_ARG;
    int rc = aos_jit_mov64(b, scratch_reg, target);
    if (rc) return rc;
    return aos_jit_put(b, aos_emit_br(scratch_reg)); /* 5 条 */
}

int aos_jit_emit_xnu_call_stub(aos_jit_buf_t *b, int64_t trap_nr) {
    if (!b) return AOS_ERR_INVALID_ARG;
    /* Mach trap 是负数，x16 里放 64 位补码，必须完整 mov64 */
    int rc = aos_jit_mov64(b, 16, (uint64_t)trap_nr);
    if (rc) return rc;
    rc = aos_jit_put(b, AOS_A64_SVC_80);
    if (rc) return rc;
    return aos_jit_put(b, AOS_A64_RET); /* 4 条装载 + svc + ret = 6 条 */
}

int aos_jit_emit_orig_trampoline(aos_jit_buf_t *b, uint64_t target,
                                 uint32_t original_insn) {
    if (!b) return AOS_ERR_INVALID_ARG;
    int rc = aos_jit_mov64(b, 16, target + 4); /* 跳过被 b 覆盖的第一条指令 */
    if (rc) return rc;
    rc = aos_jit_put(b, original_insn);         /* 就地重放原指令 */
    if (rc) return rc;
    rc = aos_jit_put(b, aos_emit_br(16));       /* 跳回原函数第 2 条指令 */
    if (rc) return rc;
    return (int)b->len;
}

uint32_t aos_jit_patch_svc_to_b(int32_t byte_offset) {
    return aos_emit_b(byte_offset);
}

void aos_jit_flush_icache(void *start, void *end) {
#if defined(__aarch64__) || defined(_M_ARM64)
    __builtin___clear_cache((char *)start, (char *)end);
#else
    (void)start; (void)end; /* x86_64 CI 上为空操作 */
#endif
}

void *aos_jit_seal(aos_jit_buf_t *b) {
    if (!b || !b->code || b->len == 0) return NULL;
    size_t bytes = b->len * sizeof(uint32_t);
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) return NULL;
    size_t page = (size_t)ps;
    size_t map_size = (bytes + page - 1) / page * page;

    void *mem = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return NULL;
    memcpy(mem, b->code, bytes);
    aos_jit_flush_icache(mem, (char *)mem + bytes);
    if (mprotect(mem, map_size, PROT_READ | PROT_EXEC) != 0) {
        munmap(mem, map_size);
        return NULL;
    }
    aos_jit_unmap(b); /* 释放上一次 seal */
    b->exec_mem = mem; b->exec_size = map_size;
    return mem;
}
