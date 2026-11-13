/*
 * A-OS 兼容层 —— 自带 rootless 越狱环境单元测试
 * 在 /tmp 下建真实目录树，跑完即清理，不污染工作区。
 * 许可证：GPL-3.0-only
 */
#include "test_util.h"
#include "aos_jailbreak.h"
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static int is_dir(const char *p) {
    struct stat st;
    return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}
static int touch(const char *path, const void *buf, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) return 0;
    size_t want = n ? n : 1;
    size_t w = n ? fwrite(buf, 1, n, f) : 1;
    fclose(f);
    return w == want;
}

int main(void) {
    char root[256], rmcmd[320], p[AOS_PATH_MAX], dir[AOS_PATH_MAX], out[AOS_PATH_MAX];
    snprintf(root, sizeof(root), "/tmp/aos_test_jbenv_%ld", (long)getpid());
    snprintf(rmcmd, sizeof(rmcmd), "rm -rf %s", root);
    if (system(rmcmd) != 0) { /* 清理失败不阻断断言 */ }

    aos_jbenv_t env;
    T_CHECK(aos_jbenv_init(&env, root) == AOS_OK, "越狱环境初始化");
    snprintf(p, sizeof(p), "%s%s", root, AOS_JB_PREFIX);
    T_CHECK(!strcmp(env.jb_root, p), "rootless 前缀拼成 root/var/jb");
    T_CHECK(strstr(env.app_home, "Containers/Data/Application") != NULL,
            "模拟 App Home 落在 iOS 容器路径下");
    T_CHECK(env.trust_cache_enabled && env.tweak_injection_enabled && env.probe_jailbroken,
            "信任缓存 / tweak 注入 / 越狱应答 默认全开");

    /* ---- 目录树 ---- */
    T_CHECK(aos_jbenv_build_layout(&env) == AOS_OK, "建目录树成功");
    T_CHECK(env.layout_built == 1, "layout_built 标记置位");
    snprintf(p, sizeof(p), "%s/var/jb/usr/lib/TweakInject", root);
    T_CHECK(is_dir(p), "TweakInject 目录存在");
    snprintf(p, sizeof(p), "%s/var/jb/usr/lib/ellekit", root);
    T_CHECK(is_dir(p), "ellekit 目录存在");
    snprintf(p, sizeof(p), "%s/var/jb/Applications", root);
    T_CHECK(is_dir(p), "Applications 目录存在");
    snprintf(p, sizeof(p), "%s/var/mobile/Containers/Data/Application", root);
    T_CHECK(is_dir(p), "模拟 App 容器根目录存在");
    snprintf(p, sizeof(p), "%s/Documents", env.app_home);
    T_CHECK(is_dir(p), "App Home/Documents 存在");
    snprintf(p, sizeof(p), "%s/Library/Caches", env.app_home);
    T_CHECK(is_dir(p), "App Home/Library/Caches 存在");
    snprintf(p, sizeof(p), "%s/tmp", env.app_home);
    T_CHECK(is_dir(p), "App Home/tmp 存在");
    snprintf(p, sizeof(p), "%s/var/jb/.aos_jailbroken", root);
    struct stat st;
    T_CHECK(stat(p, &st) == 0, "越狱标记文件存在");

    /* ---- 逻辑路径解析 ---- */
    T_CHECK(aos_jbenv_resolve(&env, "/var/jb/usr/bin/dash", out, sizeof(out)) == AOS_OK,
            "resolve /var/jb 路径");
    snprintf(p, sizeof(p), "%s/var/jb/usr/bin/dash", root);
    T_CHECK(!strcmp(out, p), "/var/jb 前缀映射到 root/var/jb");
    T_CHECK(aos_jbenv_resolve(&env,
        "/var/mobile/Containers/Data/Application/XXXX/Documents/a.txt",
        out, sizeof(out)) == AOS_OK, "resolve App Home 路径");
    snprintf(p, sizeof(p), "%s/Documents/a.txt", env.app_home);
    T_CHECK(!strcmp(out, p), "App Home 文档路径落回模拟 Home");
    T_CHECK(aos_jbenv_resolve(&env, "/private/etc/hosts", out, sizeof(out)) == AOS_OK,
            "resolve 普通绝对路径");
    snprintf(p, sizeof(p), "%s/private/etc/hosts", root);
    T_CHECK(!strcmp(out, p), "普通绝对路径收进 root，不打安卓根目录");

    /* ---- 自签信任缓存 ---- */
    uint8_t h1[AOS_CDHASH_LEN], h2[AOS_CDHASH_LEN];
    memset(h1, 0x11, sizeof(h1)); memset(h2, 0x22, sizeof(h2));
    T_CHECK(aos_jbenv_trust_add(&env, h1) == AOS_OK, "加入信任 cdhash");
    T_CHECK(aos_jbenv_trust_add(&env, h1) == AOS_OK && env.trust_count == 1,
            "重复 cdhash 去重，不重复占位");
    T_CHECK(aos_jbenv_trust_check(&env, h1) == 1, "已加入的 cdhash 命中");
    T_CHECK(aos_jbenv_trust_check(&env, h2) == 0, "未加入的 cdhash 不命中");
    T_CHECK(aos_jbenv_trust_add(&env, h2) == AOS_OK && env.trust_count == 2,
            "加入第二条 cdhash");

    snprintf(dir, sizeof(dir), "%s/var/jb/usr/lib/TweakInject", root);
    snprintf(p, sizeof(p), "%s/a.cdhash", dir);
    T_CHECK(touch(p, h1, sizeof(h1)), "写入 a.cdhash");
    snprintf(p, sizeof(p), "%s/b.cdhash", dir);
    T_CHECK(touch(p, h2, sizeof(h2)), "写入 b.cdhash");
    T_CHECK(aos_jbenv_trust_load_all(&env, dir) == 2, "从目录批量载入 2 个 cdhash");

    /* ---- tweak 扫描与 plist Filter ---- */
    snprintf(p, sizeof(p), "%s/Foo.dylib", dir);
    T_CHECK(touch(p, "x", 1), "放置 Foo.dylib");
    snprintf(p, sizeof(p), "%s/Foo.plist", dir);
    T_CHECK(touch(p, "com.target.app", 14), "放置 Foo.plist（仅注入 com.target.app）");
    snprintf(p, sizeof(p), "%s/Bar.dylib", dir);
    T_CHECK(touch(p, "x", 1), "放置 Bar.dylib（无 Filter，默认全注入）");

    aos_tweak_t tw[16]; size_t cnt = 0;
    T_CHECK(aos_jbenv_collect_tweaks(&env, "com.target.app", tw, 16, &cnt) == AOS_OK,
            "扫描 TweakInject");
    T_CHECK(cnt == 2, "com.target.app 命中 2 个 tweak（Foo + Bar）");
    T_CHECK(aos_jbenv_collect_tweaks(&env, "com.other.app", tw, 16, &cnt) == AOS_OK,
            "扫描另一个 bundle");
    T_CHECK(cnt == 1, "com.other.app 只命中无 Filter 的 Bar");

    /* ---- DYLD_INSERT_LIBRARIES 与 pspawn 继承 ---- */
    char envstr[AOS_PATH_MAX * 2];
    int n = aos_jbenv_build_insert_env(&env, "com.target.app", envstr, sizeof(envstr));
    T_CHECK(n == 2, "build_insert_env 返回 tweak 数");
    T_CHECK(strstr(envstr, "Foo.dylib") && strstr(envstr, "Bar.dylib") &&
            strchr(envstr, ':') != NULL, "注入值以冒号分隔两个 dylib");
    T_CHECK(aos_jbenv_spawn_env(&env, "com.target.app", envstr, sizeof(envstr)) == AOS_OK,
            "生成子进程继承用的环境串");
    T_CHECK(!strncmp(envstr, "DYLD_INSERT_LIBRARIES=", 22), "pspawn 注入串前缀正确");

    /* ---- 越狱检测应答 ---- */
    T_CHECK(aos_jbenv_jailbreak_probe(&env) == 1, "越狱检测应答 = 已越狱");
    env.probe_jailbroken = 0;
    T_CHECK(aos_jbenv_jailbreak_probe(&env) == 0, "关闭应答后 = 未越狱");
    env.probe_jailbroken = 1;
    aos_jbenv_dump(&env);   /* 只验证不崩溃 */

    if (system(rmcmd) != 0) { /* 清理失败不阻断断言 */ }
    T_REPORT("test_jailbreak");
}
