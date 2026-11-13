/*
 * A-OS 兼容层 —— 单元测试公共断言（不依赖任何第三方测试框架）
 * 许可证：GPL-3.0-only
 */
#ifndef AOS_TEST_UTIL_H
#define AOS_TEST_UTIL_H
#include <stdio.h>

static int g_aos_pass = 0;
static int g_aos_fail = 0;

#define T_CHECK(cond, msg) do {                                            \
    if (cond) { g_aos_pass++; }                                            \
    else {                                                                 \
        fprintf(stderr, "  [失败] %s（第 %d 行）\n", (msg), __LINE__);   \
        g_aos_fail++;                                                      \
    }                                                                      \
} while (0)

#define T_REPORT(name) do {                                                \
    printf("[%s] 通过 %d 项，失败 %d 项\n", (name), g_aos_pass, g_aos_fail);\
    return g_aos_fail ? 1 : 0;                                            \
} while (0)

#endif /* AOS_TEST_UTIL_H */
