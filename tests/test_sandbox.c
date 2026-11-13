/*
 * A-OS 兼容层 —— 沙盒目录映射与 HLE 框架桩单元测试
 * 许可证：GPL-3.0-only
 */
#include "test_util.h"
#include "aos_loader.h"
#include <string.h>
#include <stdlib.h>

int main(void) {
    aos_jbenv_t env;
    T_CHECK(aos_jbenv_init(&env, "/tmp/aos_sandbox_root") == AOS_OK,
            "初始化越狱环境（只取路径，不落盘）");
    aos_sandbox_t sb;
    T_CHECK(aos_sandbox_init(&sb, &env, "com.aiden.demo") == AOS_OK, "沙盒初始化");
    T_CHECK(strstr(sb.bundle, "com.aiden.demo.app") != NULL, "bundle 路径含 bundle id");
    T_CHECK(!strcmp(sb.jb_root, env.jb_root), "沙盒记录越狱根路径");

    char p[AOS_PATH_MAX], out[AOS_PATH_MAX];
    snprintf(p, sizeof(p), "%s/Documents", env.app_home);
    T_CHECK(!strcmp(sb.documents, p), "Documents 拼接正确");
    snprintf(p, sizeof(p), "%s/Library/Caches", env.app_home);
    T_CHECK(!strcmp(sb.caches, p), "Caches 拼接正确");
    snprintf(p, sizeof(p), "%s/tmp", env.app_home);
    T_CHECK(!strcmp(sb.tmp, p), "tmp 拼接正确");
    T_CHECK(!strcmp(sb.home, env.app_home), "home 直接复用模拟 App Home");

    /* ---- 路径改写 ---- */
    T_CHECK(aos_sandbox_translate(&sb, "/Documents/a.txt", out, sizeof(out)) == AOS_OK,
            "转换 /Documents 路径");
    snprintf(p, sizeof(p), "%s/a.txt", sb.documents);
    T_CHECK(!strcmp(out, p), "/Documents → 宿主 documents/a.txt");
    T_CHECK(aos_sandbox_translate(&sb, "/tmp/x", out, sizeof(out)) == AOS_OK,
            "转换 /tmp 路径");
    snprintf(p, sizeof(p), "%s/x", sb.tmp);
    T_CHECK(!strcmp(out, p), "/tmp → 宿主 tmp/x");
    T_CHECK(aos_sandbox_translate(&sb, "../etc/passwd", out, sizeof(out))
            == AOS_ERR_INVALID_ARG, "含 .. 的目录逃逸被拒绝");
    T_CHECK(aos_sandbox_translate(&sb, "/var/jb/usr/lib/libfoo.dylib", out, sizeof(out))
            == AOS_OK, "转换 /var/jb 前缀路径");
    snprintf(p, sizeof(p), "%s/usr/lib/libfoo.dylib", sb.jb_root);
    T_CHECK(!strcmp(out, p), "/var/jb 映射到越狱根，不误拼进 App Home");
    snprintf(p, sizeof(p), "%s/Library/x", sb.home);
    T_CHECK(aos_sandbox_translate(&sb, p, out, sizeof(out)) == AOS_OK && !strcmp(out, p),
            "Home 前缀路径原样透传");

    /* ---- HLE 框架桩登记表 ---- */
    T_CHECK(aos_hle_init() == AOS_OK, "HLE 初始化");
    T_CHECK(aos_hle_stub_count() == 13, "登记 13 个框架桩符号");
    aos_hle_fn_t fn = NULL;
    const aos_hle_stub_t *s = aos_hle_lookup("objc_msgSend", &fn);
    T_CHECK(s && fn && (s->abi_flags & 1u),
            "objc_msgSend 命中且标记为需要 JIT trampoline 加速");
    T_CHECK(aos_hle_lookup("__不存在的符号__", NULL) == NULL, "未知符号返回 NULL");
    T_CHECK(!strcmp(aos_hle_framework_name(AOS_HLE_METAL), "Metal"), "框架名映射可用");
    T_CHECK(aos_hle_framework_name(AOS_HLE_COUNT) != NULL, "越界枚举不崩溃");
    T_CHECK(aos_hle_metal_attach("libvulkan_turnip.so") == AOS_OK,
            "Metal→Vulkan 前端挂载成功");
    T_CHECK(aos_hle_metal_attach("") == AOS_ERR_INVALID_ARG, "空 ICD 名被拒绝");

    /* ---- HLE 真实现（不再是空桩） ---- */
    uint64_t h[6] = {0};
    aos_hle_set_home("/tmp/aos_hle_home");
    const char *got = (const char *)(uintptr_t)aos_hle_invoke("NSHomeDirectory", h);
    T_CHECK(got && !strcmp(got, "/tmp/aos_hle_home"),
            "NSHomeDirectory 真返回沙盒路径");
    h[0] = (uint64_t)(uintptr_t)"测试 NSLog";
    T_CHECK(aos_hle_invoke("NSLog", h) == 0, "NSLog 真输出且返回 0");
    h[0] = 0x1234;
    uint64_t c1 = (uint64_t)aos_hle_invoke("objc_getClass", h);
    uint64_t c2 = (uint64_t)aos_hle_invoke("objc_getClass", h);
    T_CHECK(c1 != 0 && c2 == c1 + 8, "objc_getClass 返回递增伪句柄");
    T_CHECK(aos_hle_invoke("sel_registerName", h) != 0,
            "sel_registerName 返回伪 SEL");
    h[0] = 0x3FF0000000000000ULL; h[1] = 0x4000000000000000ULL;
    h[2] = 0x4008000000000000ULL; h[3] = 0x4010000000000000ULL;
    uint64_t *rect = (uint64_t *)(uintptr_t)aos_hle_invoke("CGRectMake", h);
    T_CHECK(rect && rect[0] == h[0] && rect[3] == h[3],
            "CGRectMake 真构造出结构体缓冲");
    T_CHECK(aos_hle_invoke("MTLCreateSystemDefaultDevice", h) != 0,
            "Metal 设备返回伪句柄");
    h[0] = 64;
    void *mem = (void *)(uintptr_t)aos_hle_invoke("malloc", h);
    T_CHECK(mem != NULL, "malloc 真分配内存");
    if (mem) { h[0] = (uint64_t)(uintptr_t)mem; (void)aos_hle_invoke("free", h); }
    T_CHECK(aos_hle_invoke("__未知符号__", h) == 0, "未知 HLE 符号安全返回 0");

    T_REPORT("test_sandbox");
}
