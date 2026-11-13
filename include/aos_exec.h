/*
 * A-OS 兼容层 —— 执行引擎（让 guest 真正跑起来的闭环）
 *
 * 定调（总架构师反复强调的那句）：
 *   · 运行部分 = 虚拟化：IPA 自身的 arm64 机器码由硬件【原生执行】，零指令转译；
 *   · 转译部分 = JIT 加速：只在 ABI 边界（svc #0x80）生成跳板，把 XNU 调用
 *     转交给宿主裁决，然后 br 回 guest 继续执行。
 *
 * 为什么用「加载时静态预补丁」而不是内核拦截：
 *   · 不需要 KVM / 嵌套虚拟化（性能黑洞）；
 *   · 不需要 SUD / seccomp 的内核版本与权限，普通安卓进程就能跑；
 *   · 冷路径都省了 —— 陷阱点在首次执行前就已是 JIT 桩，等价于永远的热路径。
 *   SUD 层（src/syscall_dispatch.c）保留为「运行时自生成代码」的可选兜底。
 *
 * 许可证：GPL-3.0-only
 */
#ifndef AOS_EXEC_H
#define AOS_EXEC_H

#include "aos_common.h"
#include "aos_macho.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AOS_EXEC_MAX_SITES 256

typedef struct {
    uint8_t *map_base;      /* 一次性 mmap 的整块（guest + 桩区相邻） */
    size_t   map_size;
    uint8_t *guest_base;    /* guest 镜像基址 */
    size_t   guest_span;
    uint64_t min_vmaddr;    /* 镜像最小 vmaddr，用于 fileoff → 运行地址 */
    uint8_t *stub_base;     /* JIT 桩区 */
    size_t   stub_off;      /* 桩区相对 map_base 的偏移 */
    size_t   stub_size;     /* 页对齐后的桩区字节数 */
    size_t   stub_used;     /* 实际写入的字节数 */
    uint64_t slide;
    uint64_t entry;         /* 可跳转的 guest 入口（已加 slide） */
    uint32_t sites[AOS_EXEC_MAX_SITES]; /* svc #0x80 的文件偏移 */
    size_t   site_count;
    size_t   patched_count;
} aos_exec_t;

/* 扫描可执行段里的 XNU svc #0x80，输出文件偏移数组（不修改镜像） */
int aos_exec_scan_traps(const aos_macho_image_t *img,
                        uint32_t *sites, size_t cap, size_t *out_count);

/* 一次性映射 guest 与 JIT 桩区到相邻地址（保证 b 指令 ±128MB 可达），
 * 并顺带完成陷阱扫描。x86_64 上也可调用，用于验证字节生成（不执行）。 */
int aos_exec_map(const aos_macho_image_t *img, aos_exec_t *ex);
void aos_exec_unmap(aos_exec_t *ex);

/* 生成每点专属跳板 + 共享绝对跳转桩，并把所有 svc #0x80 就地改成 b <跳板>。
 * handler_addr = 宿主汇编陷阱桩 aos_guest_trap_handler 的地址；
 * 非 aarch64（如 CI 的 x86_64 字节校验）可传任意伪地址。 */
int aos_exec_patch_all(aos_exec_t *ex, const aos_macho_image_t *img,
                       uint64_t handler_addr, size_t *out_patched);

/* 跳进 guest 执行。仅 aarch64 生效；返回 >=0 为 guest 退出码，<0 为 AOS 错误码。
 * guest 的 XNU exit 不会杀掉宿主进程，而是 longjmp 回这里。 */
int aos_exec_run(aos_exec_t *ex);

/* 宿主 C 陷阱分派器（由 aarch64/ trampoline.S 的汇编桩调用）。
 * nr = x16 里的 XNU 调用号；args[0..5] = x0..x5，会被就地改写（如 open→openat）。
 * 返回 Linux 约定的结果（正常值或 -errno）。 */
int64_t aos_trap_dispatch(int64_t nr, uint64_t args[6]);

/* 累计已处理的陷阱次数（诊断 / 测试用） */
uint64_t aos_trap_count(void);

/* 生成一个含【真实 arm64 机器码】的最小 Mach-O 样本：
 *   write(1, "A-OS NATIVE OK\n", 15) → exit(42)
 * 机器码逐条由 clang --target=aarch64-linux-gnu 反汇编核对，位置无关、无需 fixups。
 * 输出缓冲区由调用方 aos_free。 */
int aos_guest_build_sample(uint8_t **out_buf, size_t *out_len);

/* 第二套样本：write 返回值（15）写回 x0 后直接作为 exit 码，
 * 用于验证宿主转译结果确实回写进 guest 寄存器。退出码应为 15。 */
int aos_guest_build_sample_ret(uint8_t **out_buf, size_t *out_len);

#ifdef __cplusplus
}
#endif
#endif /* AOS_EXEC_H */
