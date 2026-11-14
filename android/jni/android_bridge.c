/*
 * A-OS 兼容层 —— Android NativeActivity 桥接层
 *
 * 系统 dlopen libaos_compat.so 后调用 ANativeActivity_onCreate。
 * 这里不写一行 Java：兼容层本身就是纯 C + aarch64 汇编，
 * NativeActivity 直接把 Surface、AssetManager、私有目录交给我们。
 *
 * 启动流程：
 *   1. 在 App 私有目录建 rootless 越狱环境（/var/jb 布局、trust cache、
 *      TweakInject plist、DYLD_INSERT_LIBRARIES、越狱检测应答）；
 *   2. 优先从 APK assets 读 payload.decrypted（用户自己的砸壳 Mach-O），
 *      没有则回退内置的两套真实 arm64 样本；
 *   3. 扫描 __TEXT 的 svc #0x80 → JIT 就地改成 b <专属跳板>；
 *   4. 硬件原生执行 guest 机器码，XNU syscall 经宿主分派器真转发 Linux；
 *   5. 在 ANativeWindow 上直接提交第一帧。
 *
 * 定调不变：运行部分零指令转译，转译部分才是 JIT。
 * 许可证：GPL-3.0-only
 */
#include <android/native_activity.h>
#include <android/native_window.h>
#include <android/asset_manager.h>
#include <android/input.h>
#include <android/rect.h>
#include <android/log.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "aos_common.h"
#include "aos_macho.h"
#include "aos_exec.h"
#include "aos_jailbreak.h"
#include "aos_loader.h"

#define AOS_TAG "A-OS"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  AOS_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  AOS_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, AOS_TAG, __VA_ARGS__)

#if defined(__aarch64__)
extern void aos_guest_trap_handler(void);
#endif

/* ---------- 从 APK assets 读砸壳 Mach-O（拷贝到可写缓冲） ---------- */
static uint8_t *load_asset(ANativeActivity *act, const char *name, size_t *out_len) {
    if (!act || !act->assetManager || !name || !out_len) return NULL;
    AAsset *a = AAssetManager_open(act->assetManager, name, AASSET_MODE_BUFFER);
    if (!a) return NULL;
    const void *raw = AAsset_getBuffer(a);
    off_t n = AAsset_getLength(a);
    if (!raw || n <= 0) { AAsset_close(a); return NULL; }
    uint8_t *buf = (uint8_t *)aos_alloc((size_t)n);
    if (buf) {
        memcpy(buf, raw, (size_t)n);
        *out_len = (size_t)n;
    }
    AAsset_close(a);
    return buf;
}

/* ---------- 解析 → 映射 → JIT 预补丁 → 原生执行 ---------- */
static int run_image(uint8_t *buf, size_t len, int expect_rc, const char *label) {
    LOGI("──── %s ────", label);
    aos_macho_image_t img;
    int rc = aos_macho_open(buf, len, &img);
    if (rc != AOS_OK) {
        LOGE("镜像解析失败：%s", aos_status_text(rc));
        return -1;
    }
    LOGI("架构=%s 脱壳=%s 入口=0x%llx LoadCommands=%u",
         img.is_arm64e ? "arm64e（含 PAC）" : "arm64（无 PAC）",
         img.is_encrypted ? "否（拒绝执行）" : "是",
         (unsigned long long)img.entryoff, img.ncmds);
    if (img.is_encrypted) {
        LOGE("仍是 FairPlay 加密包，先砸壳再来");
        return -1;
    }

    aos_exec_t ex;
    rc = aos_exec_map(&img, &ex);
    if (rc != AOS_OK) {
        LOGE("镜像映射失败：%s", aos_status_text(rc));
        return -1;
    }
    LOGI("发现 %zu 个 XNU svc #0x80 陷阱点", ex.site_count);

#if defined(__aarch64__)
    uint64_t handler = (uint64_t)(uintptr_t)&aos_guest_trap_handler;
#else
    uint64_t handler = 0;   /* 非 arm64 设备不会走到执行分支 */
#endif
    size_t patched = 0;
    rc = aos_exec_patch_all(&ex, &img, handler, &patched);
    if (rc != AOS_OK) {
        LOGE("ABI 边界预补丁失败：%s", aos_status_text(rc));
        aos_exec_unmap(&ex);
        return -1;
    }
    LOGI("ABI 边界预补丁 %zu 处：svc → b <JIT 跳板>；"
         "guest 其余机器码一字节不动，硬件原生执行", patched);
    LOGI("开始执行 guest（零指令转译）");

    uint64_t before = aos_trap_count();
    int guest_rc = aos_exec_run(&ex);
    LOGI("guest 退出码=%d 本次陷阱数=%llu", guest_rc,
         (unsigned long long)(aos_trap_count() - before));
    aos_exec_unmap(&ex);

    if (guest_rc < 0) {
        LOGE("guest 异常返回：%s", aos_status_text(guest_rc));
        return -1;
    }
    if (expect_rc >= 0 && guest_rc != expect_rc) {
        LOGE("自测失败：期望退出码 %d，实际 %d", expect_rc, guest_rc);
        return -1;
    }
    return guest_rc;
}

/* ---------- 第一帧：直接写 ANativeWindow ----------
 * 诚实说明：这是宿主自己往 Surface 写像素，证明图形输出链路通了，
 * 还不是 UIKit / Metal 管线（那属于 M3）。 */
static void draw_first_frame(ANativeWindow *w) {
    if (!w) return;
    ANativeWindow_setBuffersGeometry(w, 0, 0, WINDOW_FORMAT_RGBA_8888);
    ANativeWindow_Buffer b;
    if (ANativeWindow_lock(w, &b, NULL) != 0) {
        LOGW("Surface 锁定失败，跳过首帧");
        return;
    }
    uint32_t *px = (uint32_t *)b.bits;
    for (int y = 0; y < b.height; y++) {
        uint32_t *row = px + (size_t)y * b.stride;
        uint8_t t = (uint8_t)((y * 255) / (b.height > 1 ? b.height - 1 : 1));
        for (int x = 0; x < b.width; x++)
            row[x] = 0xFF000000u | ((uint32_t)t << 16) | 0x00002030u;
    }
    int x0 = b.width / 3, x1 = b.width * 2 / 3;
    int y0 = b.height / 3, y1 = b.height * 2 / 3;
    for (int y = y0; y < y1; y++) {
        uint32_t *row = px + (size_t)y * b.stride;
        for (int x = x0; x < x1; x++)
            row[x] = 0xFFFF8C00u;   /* 中央色块：证明像素真的被提交 */
    }
    ANativeWindow_unlockAndPost(w);
    LOGI("第一帧已提交（宿主直写 ANativeWindow，非 UIKit/Metal 管线）");
}

/* ---------- 生命周期回调（全部给上，别让框架踩 NULL） ---------- */
static void cb_start(ANativeActivity *a)  { (void)a; LOGI("生命周期 onStart"); }
static void cb_resume(ANativeActivity *a) { (void)a; LOGI("生命周期 onResume"); }
static void cb_pause(ANativeActivity *a)  { (void)a; LOGI("生命周期 onPause"); }
static void cb_stop(ANativeActivity *a)   { (void)a; LOGI("生命周期 onStop"); }
static void cb_destroy(ANativeActivity *a){ (void)a; LOGI("生命周期 onDestroy"); }
static void *cb_save_state(ANativeActivity *a, size_t *out_len) {
    (void)a; if (out_len) *out_len = 0; return NULL;
}
static void cb_focus(ANativeActivity *a, int f) { (void)a; (void)f; }
static void cb_win_created(ANativeActivity *a, ANativeWindow *w) {
    (void)a; draw_first_frame(w);
}
static void cb_win_resized(ANativeActivity *a, ANativeWindow *w) { (void)a; (void)w; }
static void cb_win_redraw(ANativeActivity *a, ANativeWindow *w) {
    (void)a; draw_first_frame(w);
}
static void cb_win_destroyed(ANativeActivity *a, ANativeWindow *w) { (void)a; (void)w; }
static void cb_input_created(ANativeActivity *a, AInputQueue *q) { (void)a; (void)q; }
static void cb_input_destroyed(ANativeActivity *a, AInputQueue *q) { (void)a; (void)q; }
static void cb_rect(ANativeActivity *a, const ARect *r) { (void)a; (void)r; }
static void cb_config(ANativeActivity *a) { (void)a; }
static void cb_lowmem(ANativeActivity *a) {
    (void)a;
    LOGW("onLowMemory：安卓 LMK 与 iOS 内存策略不同，后续需重写进程内存分配拦截");
}

/* ---------- 入口：系统 dlsym 这个函数 ---------- */
__attribute__((visibility("default")))
void ANativeActivity_onCreate(ANativeActivity *act, void *saved_state,
                              size_t saved_state_size) {
    (void)saved_state; (void)saved_state_size;
    if (!act || !act->callbacks) return;

    ANativeActivityCallbacks *cb = act->callbacks;
    cb->onStart                   = cb_start;
    cb->onResume                  = cb_resume;
    cb->onSaveInstanceState       = cb_save_state;
    cb->onPause                   = cb_pause;
    cb->onStop                    = cb_stop;
    cb->onDestroy                 = cb_destroy;
    cb->onWindowFocusChanged      = cb_focus;
    cb->onNativeWindowCreated     = cb_win_created;
    cb->onNativeWindowResized     = cb_win_resized;
    cb->onNativeWindowRedrawNeeded= cb_win_redraw;
    cb->onNativeWindowDestroyed   = cb_win_destroyed;
    cb->onInputQueueCreated       = cb_input_created;
    cb->onInputQueueDestroyed     = cb_input_destroyed;
    cb->onContentRectChanged      = cb_rect;
    cb->onConfigurationChanged    = cb_config;
    cb->onLowMemory               = cb_lowmem;

    LOGI("════════════════════════════════════════════════");
    LOGI(" A-OS 兼容层 %s 启动", AOS_VERSION_STRING);
    LOGI("════════════════════════════════════════════════");
#if defined(__aarch64__)
    LOGI(" CPU ABI   : arm64-v8a，硬件原生执行 iOS arm64 机器码");
#else
    LOGI(" CPU ABI   : 非 arm64，执行闭环将不可用");
#endif
    LOGI(" 页大小    : %ld 字节（动态探测，兼容 4K / 16K 设备）",
         (long)sysconf(_SC_PAGESIZE));
    LOGI(" 指令转译  : 运行部分零转译；仅 ABI 边界用 JIT 跳板");

    /* 1. 自带 rootless 越狱环境 */
    aos_jbenv_t env;
    char root[1024];
    const char *priv = act->internalDataPath ? act->internalDataPath : "/data/local/tmp";
    snprintf(root, sizeof(root), "%s/jbenv", priv);
    if (aos_jbenv_init(&env, root) == AOS_OK &&
        aos_jbenv_build_layout(&env) == AOS_OK) {
        LOGI(" 越狱环境  : %s（自签 trust cache，我们就是 dyld，无需绕 AMFI）",
             env.jb_root);
        LOGI(" 越狱检测  : %s",
             aos_jbenv_jailbreak_probe(&env) ? "已越狱" : "未越狱");
        aos_hle_set_home(env.app_home);
    } else {
        LOGW(" 越狱环境  : 私有目录不可写，跳过（不影响执行闭环）");
    }

    /* 2. HLE 框架真实现 */
    aos_hle_init();
    (void)aos_hle_metal_attach("libvulkan_turnip.so");
    LOGI(" HLE 框架  : %zu 个符号已登记", aos_hle_stub_count());

    /* 3. 优先加载用户塞进 assets 的砸壳包 */
    size_t plen = 0;
    uint8_t *payload = load_asset(act, "payload.decrypted", &plen);
    if (payload) {
        LOGI(" 检测到 assets/payload.decrypted（%zu 字节），改跑用户镜像", plen);
        (void)run_image(payload, plen, -1, "用户砸壳包");
        aos_free(payload);
    } else {
        uint8_t *b1 = NULL, *b2 = NULL;
        size_t l1 = 0, l2 = 0;
        if (aos_guest_build_sample(&b1, &l1) != AOS_OK ||
            aos_guest_build_sample_ret(&b2, &l2) != AOS_OK) {
            LOGE("内置样本生成失败");
            aos_free(b1); aos_free(b2);
            return;
        }
        int r1 = run_image(b1, l1, 42, "样本 1 · write + exit(42)");
        int r2 = run_image(b2, l2, 15, "样本 2 · 返回值写回 x0");
        aos_free(b1); aos_free(b2);
        if (r1 >= 0 && r2 >= 0)
            LOGI("两套样本全部通过：write 真转发、返回值写回 x0、"
                 "陷阱后继续执行、exit 码正确传出");
        else
            LOGE("执行闭环未通过，看上面的错误行");
    }
    LOGI("════════ 启动流程结束，Surface 保持显示 ════════");
}
