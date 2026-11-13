/*
 * A-OS 兼容层 —— 自带 rootless 越狱环境
 *
 * 关键洞察（军师原地起立的地方）：
 *   我们【自己就是 Mach-O loader / dyld】，代码签名与 AMFI 的裁决权在我们手里，
 *   所以越狱环境不是"要绕过 AMFI"，而是"根本没有 AMFI 需要绕过"。
 *   Dopamine 那套 CoreTrust 注入 trust cache、PPL bypass、forkfix、
 *   jetsam multiplier 全是为了骗过真 XNU 内核 —— 在这里统统不需要。
 *   我们只需复刻【用户态可见语义】：
 *     · /var/jb 前缀的 rootless 布局（Procursus 风格）
 *     · DYLD_INSERT_LIBRARIES + TweakInject 扫描 + plist Filter
 *     · posix_spawn/execve 钩子让注入沿进程树传播（pspawn 机制）
 *     · 一个自签的"信任缓存"，让宿主 loader 认可所有砸壳 dylib
 *     · 越狱检测探针给出一致应答（/var/jb 存在、可写 /private、能 fork）
 *
 * 许可证：GPL-3.0-only
 */
#ifndef AOS_JAILBREAK_H
#define AOS_JAILBREAK_H

#include "aos_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AOS_PATH_MAX 1024
#define AOS_JB_PREFIX "/var/jb"
#define AOS_MAX_TWEAKS 256
#define AOS_MAX_TRUST  512
#define AOS_CDHASH_LEN 20   /* SHA-1 code directory hash */

typedef struct {
    char root[AOS_PATH_MAX];        /* 安卓侧真实落点（app 私有目录） */
    char jb_root[AOS_PATH_MAX];     /* root + /var/jb */
    char app_home[AOS_PATH_MAX];    /* 模拟的 iOS App Home */
    int  trust_cache_enabled;       /* 自签信任缓存是否开启 */
    int  tweak_injection_enabled;   /* 是否启用 tweak 注入 */
    int  probe_jailbroken;          /* 越狱检测应答 */
    int  layout_built;
    uint8_t trust_cache[AOS_MAX_TRUST][AOS_CDHASH_LEN];
    size_t  trust_count;
} aos_jbenv_t;

typedef struct {
    char path[AOS_PATH_MAX];
    char bundle_filter[128];
} aos_tweak_t;

/* 初始化。android_data_root 为安卓 app 的私有可写目录。
 * 传 NULL 时落到 ./aos_root（便于 CI 与单元测试）。 */
int aos_jbenv_init(aos_jbenv_t *env, const char *android_data_root);

/* 建目录树：/var/jb/{usr/lib/TweakInject,usr/bin,var/mobile/Library/Preferences,
 *   Applications,...} + App Home 的 Documents / Library/Caches / tmp */
int aos_jbenv_build_layout(aos_jbenv_t *env);

/* 拼出某个逻辑路径对应的宿主真实路径 */
int aos_jbenv_resolve(const aos_jbenv_t *env, const char *logical_path,
                      char *out, size_t cap);

/* ---- 自签信任缓存（等价于 Dopamine 的 CoreTrust 注入，但无需内核） ---- */
int  aos_jbenv_trust_add(aos_jbenv_t *env, const uint8_t cdhash[AOS_CDHASH_LEN]);
int  aos_jbenv_trust_check(const aos_jbenv_t *env, const uint8_t cdhash[AOS_CDHASH_LEN]);
int  aos_jbenv_trust_load_all(aos_jbenv_t *env, const char *dir);

/* ---- tweak 注入（对应 ElleKit / systemhook 的 libinjector） ---- */
/* 扫描 TweakInject 下的 *.dylib，按 bundle id 过滤，结果写入 tweaks */
int aos_jbenv_collect_tweaks(const aos_jbenv_t *env, const char *bundle_id,
                             aos_tweak_t *tweaks, size_t cap, size_t *out_count);
/* 拼出 DYLD_INSERT_LIBRARIES 值（冒号分隔） */
int aos_jbenv_build_insert_env(const aos_jbenv_t *env, const char *bundle_id,
                               char *out, size_t cap);
/* 生成子进程继承用的环境注入串（pspawn 语义：hook posix_spawn/execve 后附加） */
int aos_jbenv_spawn_env(const aos_jbenv_t *env, const char *bundle_id,
                        char *out, size_t cap);

/* ---- 越狱检测应答 ---- */
/* 返回 1=已越狱 0=未越狱；内部检查 /var/jb、Cydia URL scheme、fork、可写 /private */
int aos_jbenv_jailbreak_probe(const aos_jbenv_t *env);

void aos_jbenv_dump(const aos_jbenv_t *env);

#ifdef __cplusplus
}
#endif
#endif /* AOS_JAILBREAK_H */
