/*
 * A-OS 兼容层 —— 公共基础定义
 * 目标：在 ARM64 安卓上原生执行已脱壳的 iOS arm64 机器码（不做指令转译），
 *       仅对 XNU/Darwin 的 ABI 边界做用户态转译，并自带 rootless 越狱环境。
 *
 * 许可证：GPL-3.0-only（仅 GPLv3，不含 "or later"）
 */
#ifndef AOS_COMMON_H
#define AOS_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AOS_VERSION_STRING "0.3.0"

/* ---- 返回码 ---- */
enum aos_status {
    AOS_OK                =  0,
    AOS_ERR_INVALID_ARG   = -1,  /* 参数非法 */
    AOS_ERR_BAD_MAGIC     = -2,  /* 不是 Mach-O / 不是支持的魔数 */
    AOS_ERR_BAD_FORMAT    = -3,  /* 结构损坏、越界 */
    AOS_ERR_NO_SPACE      = -4,  /* header padding 不足，无法注入 */
    AOS_ERR_ENCRYPTED     = -5,  /* 仍是 FairPlay 加密包，未脱壳 */
    AOS_ERR_UNSUPPORTED   = -6,  /* 暂不支持（如 fat 多 slice、arm64e） */
    AOS_ERR_NO_MEM        = -7,
    AOS_ERR_IO            = -8,
    AOS_ERR_NOT_FOUND     = -9
};

/* ---- 全中文日志 ----
 * 桌面端走 stdout/stderr；Android App 的 stdout 默认不可见，
 * 所以 NDK 构建时统一转到 logcat（tag = A-OS），adb logcat 才能看到。 */
#ifdef __ANDROID__
#include <android/log.h>
#define AOS_LOG_INFO(fmt, ...) __android_log_print(ANDROID_LOG_INFO,  "A-OS", "[军师·信息] " fmt, ##__VA_ARGS__)
#define AOS_LOG_WARN(fmt, ...) __android_log_print(ANDROID_LOG_WARN,  "A-OS", "[军师·警告] " fmt, ##__VA_ARGS__)
#define AOS_LOG_FAIL(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, "A-OS", "[军师·骂娘] " fmt, ##__VA_ARGS__)
#else
#define AOS_LOG_INFO(fmt, ...)  do { fprintf(stdout, "[军师·信息] " fmt "\n", ##__VA_ARGS__); } while (0)
#define AOS_LOG_WARN(fmt, ...)  do { fprintf(stderr, "[军师·警告] " fmt "\n", ##__VA_ARGS__); } while (0)
#define AOS_LOG_FAIL(fmt, ...)  do { fprintf(stderr, "[军师·骂娘] " fmt "\n", ##__VA_ARGS__); } while (0)
#endif

/* ---- 显式的定宽小端读取 ----
 * 砸壳 Mach-O 与安卓 ARM64 都是小端；但 CI 跑在 x86_64、且不允许用结构体强转
 * 直接读未对齐内存（严格别名 + 对齐陷阱）。统一走 memcpy，行为确定。 */
static inline uint16_t aos_rd16(const void *p) {
    uint16_t v; memcpy(&v, p, sizeof(v)); return v;
}
static inline uint32_t aos_rd32(const void *p) {
    uint32_t v; memcpy(&v, p, sizeof(v)); return v;
}
static inline uint64_t aos_rd64(const void *p) {
    uint64_t v; memcpy(&v, p, sizeof(v)); return v;
}
static inline void aos_wr32(void *p, uint32_t v) { memcpy(p, &v, sizeof(v)); }
static inline void aos_wr64(void *p, uint64_t v) { memcpy(p, &v, sizeof(v)); }

static inline uint32_t aos_align_up(uint32_t v, uint32_t a) {
    return (v + (a - 1u)) & ~(a - 1u);
}

const char *aos_status_text(int rc);
void *aos_alloc(size_t n);
void aos_free(void *p);

#ifdef __cplusplus
}
#endif
#endif /* AOS_COMMON_H */
