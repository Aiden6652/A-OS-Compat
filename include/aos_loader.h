/*
 * A-OS 兼容层 —— Mach-O 加载器 / 沙盒 / HLE 框架桩
 * 许可证：GPL-3.0-only
 */
#ifndef AOS_LOADER_H
#define AOS_LOADER_H

#include "aos_common.h"
#include "aos_macho.h"
#include "aos_jailbreak.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 加载器 ----
 * 不要求把 __TEXT 固定映射到 0x100000000（ASLR / 安卓地址占用都可能冲突）。
 * 做法：先一次性 reserve 整个镜像跨度，再按 (vmaddr - min_vmaddr) 的相对偏移
 * MAP_FIXED 各 segment，由此得到 slide。W^X：__TEXT 为 R-X，__DATA 为 RW-。 */
typedef struct {
    uint8_t *mapped_base;     /* reserve 到的基址 */
    size_t   mapped_size;
    uint64_t slide;           /* 实际基址 - 首选 vmaddr */
    uint64_t entry;           /* 可跳转的 guest 入口（已加 slide） */
    uint64_t preferred_base;
    int      needs_chained_fixups; /* 1 = 待处理 LC_DYLD_CHAINED_FIXUPS */
    int      wx_enforced;
} aos_guest_t;

int  aos_loader_map(const aos_macho_image_t *img, aos_guest_t *out);
void aos_loader_unmap(aos_guest_t *g);

/* 应用 chained fixups 的骨架（iOS 15+）。当前完成 rebase 遍历的校验与计数，
 * 完整 bind/opcode 解释留给后续里程碑。 */
int aos_loader_apply_chained_fixups(aos_guest_t *g, const aos_macho_image_t *img,
                                    size_t *out_rebase_count);

/* ---- 沙盒目录映射 ----
 * iOS 的 NSHomeDirectory() / Documents / Library / Caches / tmp 全部重定向到
 * 安卓 app 私有目录下的 rootless 布局，避免 iOS 路径打到安卓根目录。 */
typedef struct {
    char home[AOS_PATH_MAX];
    char documents[AOS_PATH_MAX];
    char library[AOS_PATH_MAX];
    char caches[AOS_PATH_MAX];
    char tmp[AOS_PATH_MAX];
    char bundle[AOS_PATH_MAX];
    char jb_root[AOS_PATH_MAX];   /* /var/jb 逻辑前缀映射到越狱根，而不是 App Home */
} aos_sandbox_t;

int aos_sandbox_init(aos_sandbox_t *sb, const aos_jbenv_t *env,
                     const char *bundle_id);
/* 把 iOS 绝对路径改写成宿主路径；非法逃逸（..）直接拒绝 */
int aos_sandbox_translate(const aos_sandbox_t *sb, const char *ios_path,
                          char *out, size_t cap);

/* ---- HLE 框架桩 ----
 * 不加载 Apple 的 dyld_shared_cache（那是受版权保护的系统库，且是 arm64e/PAC）。
 * 走 touchHLE 验证过的高层仿真路线：自己实现 App 真正调用到的框架 API，
 * 只让 App 自身的 arm64 代码原生跑。这里登记桩表与解析入口。 */
typedef enum {
    AOS_HLE_FOUNDATION = 0,
    AOS_HLE_UIKIT      = 1,
    AOS_HLE_COREGRAPHICS = 2,
    AOS_HLE_METAL      = 3,
    AOS_HLE_OBJCRUNTIME = 4,
    AOS_HLE_LIBSYSTEM  = 5,
    AOS_HLE_COUNT
} aos_hle_framework_t;

typedef void (*aos_hle_fn_t)(void);

typedef struct {
    aos_hle_framework_t fw;
    const char *symbol;
    aos_hle_fn_t impl;
    uint32_t    abi_flags;   /* 1 = 需要 JIT trampoline 加速 */
} aos_hle_stub_t;

int aos_hle_init(void);
const aos_hle_stub_t *aos_hle_lookup(const char *symbol, aos_hle_fn_t *out_impl);
size_t aos_hle_stub_count(void);
const char *aos_hle_framework_name(aos_hle_framework_t fw);

/* Metal → Vulkan 转译前端的登记（第一帧 UI 的关口）。
 * 参考 UniXNU 已验证的链路：Metal/AIR → SPIR-V → Turnip(Mesa Vulkan/Adreno) */
int aos_hle_metal_attach(const char *vulkan_icd_name);

#ifdef __cplusplus
}
#endif
#endif /* AOS_LOADER_H */
