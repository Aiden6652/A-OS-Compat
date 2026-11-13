/*
 * A-OS 兼容层 —— 运行器：真正把砸壳 Mach-O 跑起来
 *
 * 用法：
 *   aos-run --selftest              跑两套内置样本，验证完整执行闭环
 *   aos-run <砸壳 Mach-O>           加载外部镜像并执行
 *   aos-run --emit <输出路径>       导出内置样本 Mach-O，供跨架构验证
 *
 * --selftest 的两套样本：
 *   样本 1：write(1,"A-OS NATIVE OK\n",15) → exit(42)
 *           验证陷阱转发、陷阱后继续执行、退出码传出。
 *   样本 2：write(...) 的返回值 15 直接作为 exit 码
 *           验证宿主转译结果被正确写回 guest 的 x0。
 *
 * 注意：执行部分只在 aarch64 生效；x86_64 上仍可完成解析/映射/生成跳板，
 *       但会明确拒绝执行（不会去跑 aarch64 机器码）。
 * 许可证：GPL-3.0-only
 */
#include "aos_exec.h"
#include "aos_macho.h"
#include "aos_jailbreak.h"
#include "aos_loader.h"
#include <stdlib.h>
#include <string.h>

#if defined(__aarch64__)
extern void aos_guest_trap_handler(void);
#endif

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n <= 0) { fclose(f); return NULL; }
    rewind(f);
    uint8_t *b = (uint8_t *)aos_alloc((size_t)n);
    if (!b) { fclose(f); return NULL; }
    if (fread(b, 1, (size_t)n, f) != (size_t)n) {
        aos_free(b); fclose(f); return NULL;
    }
    fclose(f); *len = (size_t)n; return b;
}

static int write_file(const char *path, const uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return AOS_ERR_IO;
    size_t w = fwrite(buf, 1, len, f);
    if (fclose(f) != 0) return AOS_ERR_IO;
    return w == len ? AOS_OK : AOS_ERR_IO;
}

static void usage(const char *prog) {
    printf("用法：\n");
    printf("  %s --selftest             两套内置样本验证完整执行闭环\n", prog);
    printf("  %s <砸壳 Mach-O>          加载并执行外部镜像\n", prog);
    printf("  %s --emit <输出路径>      导出内置样本 Mach-O\n", prog);
}

/* 加载 + JIT 预补丁 + 真正执行一个镜像缓冲区。
 * expect_rc >= 0 时校验 guest 退出码；返回 0 成功 / 1 失败 / 2 非 aarch64。
 * buf 由调用方释放。 */
static int run_buffer(uint8_t *buf, size_t len, int expect_rc, const char *label) {
    printf("════ A-OS 兼容层 · 执行引擎【%s】════\n", label);
    aos_macho_image_t img;
    int rc = aos_macho_open(buf, len, &img);
    if (rc != AOS_OK) {
        AOS_LOG_FAIL("镜像解析失败：%s", aos_status_text(rc));
        return 1;
    }
    printf("  架构       : %s（%u 条 Load Commands）\n",
           img.is_arm64e ? "arm64e（含 PAC）" : "arm64（无 PAC）", img.ncmds);
    printf("  脱壳状态   : %s\n", img.is_encrypted ? "仍加密（拒绝）" : "已脱壳");
    printf("  入口偏移   : 0x%llx\n", (unsigned long long)img.entryoff);
    if (img.is_encrypted) { AOS_LOG_FAIL("先砸壳"); return 1; }

    /* 自带 rootless 越狱环境（真实建目录，落在 /tmp 不污染工作区） */
    aos_jbenv_t env;
    if (aos_jbenv_init(&env, "/tmp/aos_run_jbenv") == AOS_OK &&
        aos_jbenv_build_layout(&env) == AOS_OK) {
        printf("  越狱环境   : %s（自签 trust cache，无需 AMFI 绕过）\n", env.jb_root);
        printf("  越狱检测   : %s\n",
               aos_jbenv_jailbreak_probe(&env) ? "已越狱" : "未越狱");
    }
    printf("  HLE 框架桩 : %zu 个符号已登记\n", aos_hle_stub_count());
    aos_hle_init();
    (void)aos_hle_metal_attach("libvulkan_turnip.so");
    /* 现场验证 HLE 不是空桩：真调用一次 NSLog 与 NSHomeDirectory */
    aos_hle_set_home(env.app_home);
    uint64_t hargs[6] = {
        (uint64_t)(uintptr_t)"HLE 框架已接管 Foundation 调用", 0, 0, 0, 0, 0
    };
    (void)aos_hle_invoke("NSLog", hargs);
    const char *hp = (const char *)(uintptr_t)aos_hle_invoke("NSHomeDirectory", hargs);
    printf("  HLE 实测   : NSHomeDirectory() → %s\n", hp);

    aos_exec_t ex;
    rc = aos_exec_map(&img, &ex);
    if (rc != AOS_OK) {
        AOS_LOG_FAIL("映射失败：%s", aos_status_text(rc));
        return 1;
    }
    printf("  陷阱点     : %zu 个 XNU svc #0x80\n", ex.site_count);

#if defined(__aarch64__)
    uint64_t handler = (uint64_t)(uintptr_t)&aos_guest_trap_handler;
#else
    uint64_t handler = 0x400000ULL;   /* 仅用于字节生成校验，不执行 */
#endif
    size_t patched = 0;
    rc = aos_exec_patch_all(&ex, &img, handler, &patched);
    if (rc != AOS_OK) {
        AOS_LOG_FAIL("JIT 预补丁失败：%s", aos_status_text(rc));
        aos_exec_unmap(&ex); return 1;
    }
    printf("  JIT 预补丁 : %zu 处 svc → b <跳板>，其余机器码原样原生执行\n", patched);
    printf("──── 开始执行 guest（硬件原生 arm64 指令）────\n");
    fflush(stdout);

    uint64_t before = aos_trap_count();
    int guest_rc = aos_exec_run(&ex);
    uint64_t traps = aos_trap_count() - before;

    printf("──── guest 已返回 ────\n");
    if (guest_rc == AOS_ERR_UNSUPPORTED) {
        printf("  当前环境非 aarch64：解析/映射/JIT 跳板已全部完成，"
               "但执行需要 ARM64 设备（CI 里用 qemu-aarch64 验证）。\n");
        aos_exec_unmap(&ex); return 2;
    }
    if (guest_rc < 0) {
        AOS_LOG_FAIL("guest 异常返回：%s", aos_status_text(guest_rc));
        aos_exec_unmap(&ex); return 1;
    }
    printf("  guest 退出码 : %d\n", guest_rc);
    printf("  本次陷阱数   : %llu（全部经 ABI 边界转译）\n",
           (unsigned long long)traps);
    printf("════ 执行完毕 ════\n");

    aos_exec_unmap(&ex);
    if (expect_rc >= 0 && guest_rc != expect_rc) {
        AOS_LOG_FAIL("自测失败：期望退出码 %d，实际 %d", expect_rc, guest_rc);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    int selftest = 0, emit = 0;
    const char *path = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--selftest")) selftest = 1;
        else if (!strcmp(argv[i], "--emit")) { emit = 1; if (i + 1 < argc) path = argv[++i]; }
        else if (!path) path = argv[i];
        else { usage(argv[0]); return 2; }
    }
    if ((!selftest && !emit && !path) || (emit && !path)) { usage(argv[0]); return 2; }

    if (emit) {
        uint8_t *buf = NULL; size_t len = 0;
        if (aos_guest_build_sample(&buf, &len) != AOS_OK) {
            AOS_LOG_FAIL("生成内置样本失败"); return 1;
        }
        int rc = write_file(path, buf, len);
        aos_free(buf);
        if (rc != AOS_OK) { AOS_LOG_FAIL("写不出样本文件：%s", path); return 1; }
        printf("已导出内置 arm64 样本：%s（%zu 字节，含 2 个 svc #0x80）\n", path, len);
        return 0;
    }

    if (selftest) {
        uint8_t *b1 = NULL; size_t l1 = 0;
        uint8_t *b2 = NULL; size_t l2 = 0;
        if (aos_guest_build_sample(&b1, &l1) != AOS_OK ||
            aos_guest_build_sample_ret(&b2, &l2) != AOS_OK) {
            AOS_LOG_FAIL("生成内置样本失败"); aos_free(b1); aos_free(b2); return 1;
        }
        int r1 = run_buffer(b1, l1, 42, "样本 1 · write + exit(42)");
        int r2 = run_buffer(b2, l2, 15, "样本 2 · 返回值写回 x0");
        aos_free(b1); aos_free(b2);
        if (r1 || r2) return (r1 == 2 || r2 == 2) ? 2 : 1;
        printf("两套样本全部通过：write 真转发、返回值写回 x0、"
               "陷阱后继续执行、exit 码正确传出。\n");
        return 0;
    }

    size_t len = 0;
    uint8_t *buf = read_file(path, &len);
    if (!buf) { AOS_LOG_FAIL("读不了镜像：%s", path); return 1; }
    int rc = run_buffer(buf, len, -1, "外部镜像");
    aos_free(buf);
    return rc;
}
