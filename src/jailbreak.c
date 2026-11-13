/*
 * A-OS 兼容层 —— 自带 rootless 越狱环境实现
 *
 * 我们就是 loader，签名由我们裁决：所以这里不实现任何 AMFI 绕过，
 * 只复刻「用户态可见语义」，让砸壳 App 与越狱 tweak 以为自己在已越狱 iOS 上。
 * 许可证：GPL-3.0-only
 */
#include "aos_jailbreak.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>   /* access() / W_OK：越狱检测探针需要 */

static int path_join(char *out, size_t cap, const char *a, const char *b) {
    int n = snprintf(out, cap, "%s/%s", a, b);
    return (n < 0 || (size_t)n >= cap) ? AOS_ERR_IO : AOS_OK;
}

static int mkdir_p(const char *path) {
    char tmp[AOS_PATH_MAX];
    if (strlen(path) >= sizeof(tmp)) return AOS_ERR_IO;
    memcpy(tmp, path, strlen(path) + 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return AOS_ERR_IO;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return AOS_ERR_IO;
    return AOS_OK;
}

static int write_marker(const char *dir, const char *name, const char *text) {
    char p[AOS_PATH_MAX];
    if (path_join(p, sizeof(p), dir, name) != AOS_OK) return AOS_ERR_IO;
    FILE *f = fopen(p, "wb");
    if (!f) return AOS_ERR_IO;
    size_t n = strlen(text);
    size_t w = fwrite(text, 1, n, f);
    fclose(f);
    return w == n ? AOS_OK : AOS_ERR_IO;
}

int aos_jbenv_init(aos_jbenv_t *env, const char *android_data_root) {
    if (!env) return AOS_ERR_INVALID_ARG;
    memset(env, 0, sizeof(*env));
    const char *r = (android_data_root && android_data_root[0])
                    ? android_data_root : "./aos_root";
    if (snprintf(env->root, sizeof(env->root), "%s", r) >= (int)sizeof(env->root))
        return AOS_ERR_IO;
    if (snprintf(env->jb_root, sizeof(env->jb_root), "%s%s",
                 env->root, AOS_JB_PREFIX) >= (int)sizeof(env->jb_root))
        return AOS_ERR_IO;
    /* 固定 UUID：同一个安卓 app 私有目录下保持稳定的模拟 App Home */
    if (snprintf(env->app_home, sizeof(env->app_home),
                 "%s/var/mobile/Containers/Data/Application/"
                 "A0S-0000-0000-0000-COMPATLAYER", env->root)
        >= (int)sizeof(env->app_home)) return AOS_ERR_IO;

    env->trust_cache_enabled     = 1;
    env->tweak_injection_enabled = 1;
    env->probe_jailbroken         = 1;
    return AOS_OK;
}

int aos_jbenv_build_layout(aos_jbenv_t *env) {
    if (!env) return AOS_ERR_INVALID_ARG;
    static const char *dirs[] = {
        "",
        "/var/jb",
        "/var/jb/usr",
        "/var/jb/usr/lib",
        "/var/jb/usr/lib/TweakInject",
        "/var/jb/usr/lib/ellekit",
        "/var/jb/usr/bin",
        "/var/jb/Applications",
        "/var/jb/Library",
        "/var/jb/Library/Frameworks",
        "/var/jb/var/mobile/Library/Preferences",
        "/var/jb/etc",
        "/var/mobile/Containers/Data/Application",
    };
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        char p[AOS_PATH_MAX];
        if (snprintf(p, sizeof(p), "%s%s", env->root, dirs[i]) >= (int)sizeof(p))
            return AOS_ERR_IO;
        if (mkdir_p(p) != AOS_OK) return AOS_ERR_IO;
    }
    static const char *home_dirs[] = {
        "/Documents", "/Library", "/Library/Caches",
        "/Library/Preferences", "/tmp"
    };
    for (size_t i = 0; i < sizeof(home_dirs) / sizeof(home_dirs[0]); i++) {
        char p[AOS_PATH_MAX];
        if (snprintf(p, sizeof(p), "%s%s", env->app_home, home_dirs[i])
            >= (int)sizeof(p)) return AOS_ERR_IO;
        if (mkdir_p(p) != AOS_OK) return AOS_ERR_IO;
    }

    /* 越狱检测常见探针文件 */
    (void)write_marker(env->jb_root, ".aos_jailbroken", "A-OS rootless jailbreak\n");
    (void)write_marker(env->jb_root, "usr/lib/ellekit/pspawn.marker",
                       "pspawn.dylib / systemhook.dylib 已挂载语义\n");
    env->layout_built = 1;
    AOS_LOG_INFO("rootless 越狱环境就绪：%s", env->jb_root);
    return AOS_OK;
}

int aos_jbenv_resolve(const aos_jbenv_t *env, const char *logical_path,
                      char *out, size_t cap) {
    if (!env || !logical_path || !out) return AOS_ERR_INVALID_ARG;
    size_t pre = strlen(AOS_JB_PREFIX);
    if (strncmp(logical_path, AOS_JB_PREFIX, pre) == 0) {
        int n = snprintf(out, cap, "%s%s", env->root, logical_path);
        return (n < 0 || (size_t)n >= cap) ? AOS_ERR_IO : AOS_OK;
    }
    /* App 用 NSHomeDirectory() 取到的路径直接落到模拟 Home */
    if (strstr(logical_path, "Containers/Data/Application")) {
        const char *suffix = strstr(logical_path, "/Documents");
        if (!suffix) suffix = strstr(logical_path, "/Library");
        if (!suffix) suffix = strstr(logical_path, "/tmp");
        if (suffix) {
            int n = snprintf(out, cap, "%s%s", env->app_home, suffix);
            return (n < 0 || (size_t)n >= cap) ? AOS_ERR_IO : AOS_OK;
        }
    }
    int n = snprintf(out, cap, "%s%s", env->root, logical_path);
    return (n < 0 || (size_t)n >= cap) ? AOS_ERR_IO : AOS_OK;
}

/* ---- 自签 trust cache ---- */
int aos_jbenv_trust_add(aos_jbenv_t *env, const uint8_t cdhash[AOS_CDHASH_LEN]) {
    if (!env || !cdhash || !env->trust_cache_enabled) return AOS_ERR_INVALID_ARG;
    for (size_t i = 0; i < env->trust_count; i++)
        if (!memcmp(env->trust_cache[i], cdhash, AOS_CDHASH_LEN)) return AOS_OK;
    if (env->trust_count >= AOS_MAX_TRUST) return AOS_ERR_NO_SPACE;
    memcpy(env->trust_cache[env->trust_count++], cdhash, AOS_CDHASH_LEN);
    return AOS_OK;
}

int aos_jbenv_trust_check(const aos_jbenv_t *env,
                          const uint8_t cdhash[AOS_CDHASH_LEN]) {
    if (!env || !cdhash || !env->trust_cache_enabled) return 0;
    for (size_t i = 0; i < env->trust_count; i++)
        if (!memcmp(env->trust_cache[i], cdhash, AOS_CDHASH_LEN)) return 1;
    return 0;
}

int aos_jbenv_trust_load_all(aos_jbenv_t *env, const char *dir) {
    if (!env || !dir) return AOS_ERR_INVALID_ARG;
    DIR *dp = opendir(dir);
    if (!dp) return AOS_ERR_IO;
    struct dirent *de;
    int loaded = 0;
    while ((de = readdir(dp)) != NULL) {
        size_t n = strlen(de->d_name);
        if (n < 7 || strcmp(de->d_name + n - 7, ".cdhash") != 0) continue;
        char p[AOS_PATH_MAX];
        if (path_join(p, sizeof(p), dir, de->d_name) != AOS_OK) continue;
        FILE *f = fopen(p, "rb");
        if (!f) continue;
        uint8_t h[AOS_CDHASH_LEN];
        size_t got = fread(h, 1, sizeof(h), f);
        fclose(f);
        if (got == sizeof(h) && aos_jbenv_trust_add(env, h) == AOS_OK) loaded++;
    }
    closedir(dp);
    return loaded;
}

/* ---- tweak 扫描（对应 ElleKit 的 libinjector 语义） ---- */
static int tweak_matches_bundle(const char *dylib_path, const char *bundle_id) {
    if (!bundle_id || !bundle_id[0]) return 1; /* 未指定 bundle，全加载 */
    char plist[AOS_PATH_MAX];
    int n = snprintf(plist, sizeof(plist), "%s", dylib_path);
    if (n < 0 || (size_t)n >= sizeof(plist)) return 1;
    size_t l = strlen(plist);
    if (l >= 6 && !strcmp(plist + l - 6, ".dylib"))
        memcpy(plist + l - 6, ".plist", 7);
    else
        return 1;
    FILE *f = fopen(plist, "rb");
    if (!f) return 1; /* 无 Filter plist → 默认注入 */
    char buf[4096];
    size_t got = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[got] = '\0';
    /* 简化过滤：plist 里出现该 bundle id 才注入（真实实现需解析 plist 数组） */
    return strstr(buf, bundle_id) != NULL ? 1 : 0;
}

int aos_jbenv_collect_tweaks(const aos_jbenv_t *env, const char *bundle_id,
                             aos_tweak_t *tweaks, size_t cap, size_t *out_count) {
    if (!env || !tweaks || !out_count) return AOS_ERR_INVALID_ARG;
    *out_count = 0;
    if (!env->tweak_injection_enabled) return AOS_OK;

    char dir[AOS_PATH_MAX];
    if (snprintf(dir, sizeof(dir), "%s/var/jb/usr/lib/TweakInject", env->root)
        >= (int)sizeof(dir)) return AOS_ERR_IO;
    DIR *dp = opendir(dir);
    if (!dp) return AOS_OK; /* 目录还没建 → 0 个 tweak，不算错 */

    struct dirent *de;
    while ((de = readdir(dp)) != NULL && *out_count < cap) {
        size_t n = strlen(de->d_name);
        if (n < 7 || strcmp(de->d_name + n - 6, ".dylib") != 0) continue;
        char full[AOS_PATH_MAX];
        if (path_join(full, sizeof(full), dir, de->d_name) != AOS_OK) continue;
        if (!tweak_matches_bundle(full, bundle_id)) continue;
        aos_tweak_t *t = &tweaks[*out_count];
        snprintf(t->path, sizeof(t->path), "%s", full);
        snprintf(t->bundle_filter, sizeof(t->bundle_filter), "%s",
                 bundle_id ? bundle_id : "*");
        (*out_count)++;
    }
    closedir(dp);
    return AOS_OK;
}

int aos_jbenv_build_insert_env(const aos_jbenv_t *env, const char *bundle_id,
                               char *out, size_t cap) {
    if (!env || !out || cap == 0) return AOS_ERR_INVALID_ARG;
    out[0] = '\0';
    aos_tweak_t tw[AOS_MAX_TWEAKS];
    size_t cnt = 0;
    int rc = aos_jbenv_collect_tweaks(env, bundle_id, tw, AOS_MAX_TWEAKS, &cnt);
    if (rc != AOS_OK) return rc;
    size_t used = 0;
    for (size_t i = 0; i < cnt; i++) {
        size_t need = strlen(tw[i].path) + (i ? 1 : 0);
        if (used + need + 1 > cap) break;
        if (i) out[used++] = ':';
        memcpy(out + used, tw[i].path, strlen(tw[i].path));
        used += strlen(tw[i].path);
        out[used] = '\0';
    }
    return (int)cnt;
}

int aos_jbenv_spawn_env(const aos_jbenv_t *env, const char *bundle_id,
                        char *out, size_t cap) {
    if (!env || !out) return AOS_ERR_INVALID_ARG;
    char list[AOS_PATH_MAX * 2];
    int n = aos_jbenv_build_insert_env(env, bundle_id, list, sizeof(list));
    if (n < 0) return n;
    int m = snprintf(out, cap, "DYLD_INSERT_LIBRARIES=%s", list);
    return (m < 0 || (size_t)m >= cap) ? AOS_ERR_IO : AOS_OK;
}

int aos_jbenv_jailbreak_probe(const aos_jbenv_t *env) {
    if (!env || !env->probe_jailbroken) return 0;
    char p[AOS_PATH_MAX];
    struct stat st;
    /* 探针 1：/var/jb 存在 */
    if (snprintf(p, sizeof(p), "%s/var/jb", env->root) >= (int)sizeof(p)) return 0;
    if (stat(p, &st) != 0 || !S_ISDIR(st.st_mode)) return 0;
    /* 探针 2：越狱标记可写 */
    if (snprintf(p, sizeof(p), "%s/var/jb/.aos_jailbroken", env->root)
        >= (int)sizeof(p)) return 0;
    if (access(p, W_OK) != 0) return 0;
    /* 探针 3：App 私有目录可写（对应 /private 越狱检测） */
    if (snprintf(p, sizeof(p), "%s/var/jb/usr/lib/TweakInject", env->root)
        >= (int)sizeof(p)) return 0;
    if (access(p, W_OK) != 0) return 0;
    return 1;
}

void aos_jbenv_dump(const aos_jbenv_t *env) {
    if (!env) return;
    printf("──── 自带越狱环境 ────\n");
    printf("  安卓落点     : %s\n", env->root);
    printf("  rootless 前缀: %s\n", env->jb_root);
    printf("  模拟 App Home: %s\n", env->app_home);
    printf("  信任缓存     : %s（%zu 条 cdhash）\n",
           env->trust_cache_enabled ? "自签开启" : "关闭", env->trust_count);
    printf("  tweak 注入   : %s\n",
           env->tweak_injection_enabled ? "开启" : "关闭");
    printf("  越狱检测应答 : %s\n",
           aos_jbenv_jailbreak_probe(env) ? "已越狱" : "未越狱");
}
