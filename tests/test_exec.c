/*
 * A-OS 兼容层 —— 执行引擎单元测试（x86_64 / aarch64 均可编译运行）
 *
 * x86_64 上验证：真实 arm64 样本构造、陷阱扫描、相邻映射、
 *                JIT 跳板字节正确性、C 分派器逻辑（不执行 guest 机器码）。
 * aarch64 实机上的执行闭环由 CI 的 qemu-aarch64 冒烟步骤覆盖。
 * 许可证：GPL-3.0-only
 */
#include "test_util.h"
#include "aos_exec.h"
#include "aos_macho.h"
#include "aos_jit.h"
#include <string.h>

int main(void) {
    /* ---- 1. 内置真实 arm64 样本 ---- */
    uint8_t *buf = NULL; size_t len = 0;
    T_CHECK(aos_guest_build_sample(&buf, &len) == AOS_OK, "生成内置 arm64 样本");
    T_CHECK(buf && len == 0x2000u, "样本为 8KiB thin Mach-O");
    if (!buf) T_REPORT("test_exec");
    T_CHECK(aos_rd32(buf) == AOS_MH_MAGIC_64, "样本魔数为 MH_MAGIC_64");
    T_CHECK(aos_rd32(buf + 0x1000) == 0xD2800020u, "样本首条指令 mov x0,#1");
    T_CHECK(aos_rd32(buf + 0x1004) == 0x10000101u, "样本 adr x1,0x24（位置无关）");
    T_CHECK(aos_rd32(buf + 0x1010) == AOS_A64_SVC_80, "样本 +0x10 是 svc #0x80");
    T_CHECK(aos_rd32(buf + 0x101C) == AOS_A64_SVC_80, "样本 +0x1C 是 svc #0x80");
    T_CHECK(!memcmp(buf + 0x1024, "A-OS NATIVE OK\n", 15), "样本内嵌字符串正确");

    /* ---- 2. 解析 ---- */
    aos_macho_image_t img;
    T_CHECK(aos_macho_open(buf, len, &img) == AOS_OK, "样本可被解析器打开");
    T_CHECK(img.ncmds == 2 && img.entryoff == 0x1000ULL, "2 条 LC，入口 0x1000");
    T_CHECK(img.first_section_off == 0x1000u, "__text section 偏移 0x1000");
    T_CHECK(img.is_encrypted == 0 && img.is_arm64e == 0,
            "样本是未加密的普通 arm64（无 PAC）");

    /* ---- 3. 陷阱扫描 ---- */
    uint32_t sites[16]; size_t cnt = 0;
    T_CHECK(aos_exec_scan_traps(&img, sites, 16, &cnt) == AOS_OK, "扫描陷阱");
    T_CHECK(cnt == 2, "扫出 2 个 XNU svc #0x80");
    T_CHECK(sites[0] == 0x1010u && sites[1] == 0x101Cu,
            "陷阱点文件偏移为 0x1010 / 0x101C");

    /* ---- 4. 一次性相邻映射 ---- */
    aos_exec_t ex;
    T_CHECK(aos_exec_map(&img, &ex) == AOS_OK, "guest + 桩区一次性映射成功");
    if (!ex.map_base) { aos_free(buf); T_REPORT("test_exec"); }
    T_CHECK(ex.guest_base == ex.map_base, "guest 位于映射块起始");
    T_CHECK(ex.stub_base > ex.guest_base, "JIT 桩区紧随 guest（保证 b 可达）");
    T_CHECK(ex.stub_off % 4096u == 0, "桩区起始页对齐");
    T_CHECK(ex.site_count == 2, "映射时记录了 2 个陷阱点");
    T_CHECK(ex.entry == (uint64_t)(uintptr_t)ex.guest_base + 0x1000u,
            "入口运行地址 = 映射基址 + entryoff");
    T_CHECK((uint64_t)(uintptr_t)ex.stub_base - ex.entry < (128u * 1024u * 1024u),
            "桩区落在 b 指令 ±128MB 范围内");

    /* ---- 5. JIT 预补丁 ---- */
    size_t patched = 0;
    T_CHECK(aos_exec_patch_all(&ex, &img, 0x400000ULL, &patched) == AOS_OK,
            "JIT 预补丁执行成功");
    T_CHECK(patched == 2 && ex.patched_count == 2, "2 处 svc 被覆盖");
    T_CHECK(ex.stub_used == (5 + 2 * 5) * 4u, "桩区共写出 15 条指令（60 字节）");

    const uint32_t *c = (const uint32_t *)ex.stub_base;
    uint64_t shared = (uint64_t)(uintptr_t)ex.stub_base;

    /* 共享桩：mov64 x17, handler ; br x17 */
    T_CHECK(c[0] == aos_emit_movz(17, (uint16_t)(0x400000ULL & 0xFFFFu), 0),
            "共享桩第 1 条为 movz x17");
    T_CHECK(c[1] == aos_emit_movk(17, (uint16_t)((0x400000ULL >> 16) & 0xFFFFu), 1),
            "共享桩第 2 条为 movk x17, lsl#16");
    T_CHECK(c[2] == aos_emit_movk(17, 0, 2) && c[3] == aos_emit_movk(17, 0, 3),
            "共享桩高两段为 0");
    T_CHECK(c[4] == aos_emit_br(17), "共享桩以 br x17 绝对跳到宿主陷阱桩");

    /* 每点专属桩：mov64 x9, 返回地址 ; b <共享桩> */
    for (size_t i = 0; i < 2; i++) {
        size_t k = 5 + i * 5;
        uint64_t svc_addr = (uint64_t)(uintptr_t)ex.guest_base
                          + (i == 0 ? 0x1010u : 0x101Cu);
        uint64_t ret = svc_addr + 4;
        T_CHECK(c[k + 0] == aos_emit_movz(9, (uint16_t)(ret & 0xFFFFu), 0) &&
                c[k + 1] == aos_emit_movk(9, (uint16_t)((ret >> 16) & 0xFFFFu), 1) &&
                c[k + 2] == aos_emit_movk(9, (uint16_t)((ret >> 32) & 0xFFFFu), 2) &&
                c[k + 3] == aos_emit_movk(9, (uint16_t)((ret >> 48) & 0xFFFFu), 3),
                i == 0 ? "桩 1 装载 guest 返回地址到 x9" : "桩 2 装载 guest 返回地址到 x9");
        uint64_t here = (uint64_t)(uintptr_t)&c[k + 4];
        T_CHECK(c[k + 4] == aos_emit_b((int32_t)((int64_t)shared - (int64_t)here)),
                i == 0 ? "桩 1 以 b 汇入共享桩（不碰 x30）" : "桩 2 以 b 汇入共享桩（不碰 x30）");

        /* guest 里的 svc 已被改成 b <该点桩> */
        uint64_t point = (uint64_t)(uintptr_t)&c[k];
        uint32_t expect = aos_emit_b((int32_t)((int64_t)point - (int64_t)svc_addr));
        uint32_t actual = aos_rd32(ex.guest_base + (i == 0 ? 0x1010u : 0x101Cu));
        T_CHECK(actual == expect && (actual & 0xFC000000u) == 0x14000000u,
                i == 0 ? "guest 陷阱点 1 已改为 b 指令" : "guest 陷阱点 2 已改为 b 指令");
    }

    /* 除两处陷阱外，guest 机器码一字节没动 */
    T_CHECK(aos_rd32(ex.guest_base + 0x1000) == 0xD2800020u, "guest 非陷阱指令保持原样");
    T_CHECK(aos_rd32(ex.guest_base + 0x1014) == 0xD2800540u, "guest mov x0,#42 保持原样");
    T_CHECK(!memcmp(ex.guest_base + 0x1024, "A-OS NATIVE OK\n", 15),
            "guest 数据区字符串保持原样");

    /* ---- 6. C 陷阱分派器（x86_64 上验证逻辑，不真发 Linux syscall） ---- */
    uint64_t a[6] = {42, 0, 0, 0, 0, 0};
    uint64_t before = aos_trap_count();
    T_CHECK(aos_trap_dispatch(1, a) == 0,
            "XNU exit 被特判：不真杀宿主进程，无 jumpbuf 时返回 0");
    T_CHECK(aos_trap_dispatch(-31, a) == 0,
            "mach_msg 走用户态模拟，返回 MACH_MSG_SUCCESS");
    T_CHECK(aos_trap_dispatch(-28, a) == 0x0A05,
            "task_self 返回伪端口句柄");
    T_CHECK(aos_trap_dispatch(26, a) == -38,
            "ptrace 被明确拒绝，返回 -ENOSYS");
    T_CHECK(aos_trap_dispatch(9999, a) == -38,
            "未收录调用号返回 -ENOSYS");
    T_CHECK(aos_trap_count() == before + 5, "陷阱计数正确累加");

    /* ---- 7. 非 aarch64 上拒绝执行（不误跑 guest 机器码） ---- */
#if !defined(__aarch64__)
    T_CHECK(aos_exec_run(&ex) == AOS_ERR_UNSUPPORTED,
            "x86_64 上执行引擎明确返回 UNSUPPORTED");
#endif

    aos_exec_unmap(&ex);
    T_CHECK(ex.map_base == NULL && ex.entry == 0, "unmap 后执行上下文归零");
    aos_free(buf);

    /* ---- 8. 第二套样本：返回值写回 x0 ---- */
    uint8_t *b2 = NULL; size_t l2 = 0;
    T_CHECK(aos_guest_build_sample_ret(&b2, &l2) == AOS_OK,
            "生成返回值写回样本");
    if (b2) {
        T_CHECK(aos_rd32(b2 + 0x1004) == 0x100000E1u,
                "ret 样本 adr x1,0x20 编码正确");
        T_CHECK(aos_rd32(b2 + 0x1010) == AOS_A64_SVC_80 &&
                aos_rd32(b2 + 0x1018) == AOS_A64_SVC_80,
                "ret 样本两个陷阱点在 0x1010 / 0x1018");
        T_CHECK(aos_rd32(b2 + 0x1014) == 0xD2800030u,
                "ret 样本两次 svc 之间没有覆盖 x0 的指令");
        T_CHECK(!memcmp(b2 + 0x1020, "A-OS NATIVE OK\n", 15),
                "ret 样本字符串位置正确");
        aos_macho_image_t img2;
        T_CHECK(aos_macho_open(b2, l2, &img2) == AOS_OK, "ret 样本可解析");
        uint32_t s2[16]; size_t c2 = 0;
        T_CHECK(aos_exec_scan_traps(&img2, s2, 16, &c2) == AOS_OK && c2 == 2,
                "ret 样本扫出 2 个陷阱点");
        T_CHECK(s2[0] == 0x1010u && s2[1] == 0x1018u, "ret 样本陷阱偏移正确");
        aos_exec_t ex2;
        if (aos_exec_map(&img2, &ex2) == AOS_OK) {
            size_t p2 = 0;
            T_CHECK(aos_exec_patch_all(&ex2, &img2, 0x400000ULL, &p2) == AOS_OK
                    && p2 == 2, "ret 样本完成 2 处 JIT 预补丁");
            const uint32_t *d = (const uint32_t *)ex2.stub_base;
            uint64_t ret2 = (uint64_t)(uintptr_t)ex2.guest_base + 0x1018u + 4u;
            T_CHECK(d[10] == aos_emit_movz(9, (uint16_t)(ret2 & 0xFFFFu), 0) &&
                    d[11] == aos_emit_movk(9, (uint16_t)((ret2 >> 16) & 0xFFFFu), 1),
                    "ret 样本第 2 个跳板装载了正确的 guest 返回地址");
            aos_exec_unmap(&ex2);
        } else {
            T_CHECK(0, "ret 样本映射成功");
        }
        aos_free(b2);
    }

    T_REPORT("test_exec");
}
