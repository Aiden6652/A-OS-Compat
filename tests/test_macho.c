/*
 * A-OS 兼容层 —— Mach-O 解析与 dylib 注入单元测试
 * 许可证：GPL-3.0-only
 */
#include "test_util.h"
#include "test_macho_fixture.h"
#include "aos_macho.h"
#include <stdlib.h>
#include <string.h>

typedef struct { size_t count; uint32_t last_cmd; } lc_ctx_t;

static int lc_visitor(uint32_t cmd, uint32_t cmdsize, const uint8_t *lc, void *ctx) {
    lc_ctx_t *c = (lc_ctx_t *)ctx;
    c->count++; c->last_cmd = cmd;
    (void)cmdsize; (void)lc;
    return AOS_OK;
}

int main(void) {
    size_t len = 0;
    uint8_t *thin = tfi_make_thin(&len);
    T_CHECK(thin != NULL, "夹具构造 thin 成功");
    if (!thin) T_REPORT("test_macho");

    /* ---- 1. 解析合法镜像 ---- */
    aos_macho_image_t img;
    int rc = aos_macho_open(thin, len, &img);
    T_CHECK(rc == AOS_OK, "打开合法 thin 返回 AOS_OK");
    T_CHECK(img.cpu_type == AOS_CPU_TYPE_ARM64, "cputype = ARM64");
    T_CHECK(img.filetype == AOS_MH_EXECUTE, "filetype = MH_EXECUTE");
    T_CHECK(img.ncmds == 2, "ncmds = 2");
    T_CHECK(img.sizeofcmds == 176u, "sizeofcmds = 152+24 = 176");
    T_CHECK(img.header_end == 208u, "header_end = 32+176 = 208");
    T_CHECK(img.text_vmaddr == 0x100000000ULL, "__TEXT 首选地址 0x100000000");
    T_CHECK(img.entryoff == 0x800ULL, "LC_MAIN entryoff = 0x800");
    T_CHECK(img.first_section_off == TFI_SECTION_OFF, "首个 section 偏移 = 0x1000");
    T_CHECK(img.is_encrypted == 0, "未加密（cryptid = 0）");
    T_CHECK(img.is_arm64e == 0, "普通 arm64，无 PAC");
    T_CHECK(img.has_chained_fixups == 0, "经典 fixups");

    /* ---- 2. 遍历 Load Commands ---- */
    lc_ctx_t ctx = {0, 0};
    T_CHECK(aos_macho_foreach_lc(&img, lc_visitor, &ctx) == AOS_OK, "遍历返回 OK");
    T_CHECK(ctx.count == 2, "遍历到 2 条 LC");

    /* ---- 3~5. 异常输入 ---- */
    uint8_t *bad = (uint8_t *)malloc(len);
    aos_macho_image_t tmp;
    memcpy(bad, thin, len); aos_wr32(bad, 0xDEADBEEFu);
    T_CHECK(aos_macho_open(bad, len, &tmp) == AOS_ERR_BAD_MAGIC, "坏魔数 → BAD_MAGIC");
    memcpy(bad, thin, len); aos_wr32(bad + 4, 0x01000007u);
    T_CHECK(aos_macho_open(bad, len, &tmp) == AOS_ERR_UNSUPPORTED, "非 arm64 → UNSUPPORTED");
    memcpy(bad, thin, len); aos_wr32(bad + 8, AOS_CPU_SUBTYPE_ARM64E);
    T_CHECK(aos_macho_open(bad, len, &tmp) == AOS_OK, "arm64e 仍可解析");
    T_CHECK(tmp.is_arm64e == 1, "arm64e 被标记（含 PAC，本项目不碰）");
    free(bad);

    /* ---- 6. 核心：注入 ---- */
    const char *path = "@executable_path/AOSTweak.dylib";
    uint8_t *out = NULL; size_t out_len = 0;
    rc = aos_macho_inject_dylib(thin, len, path, AOS_LC_LOAD_DYLIB, &out, &out_len);
    T_CHECK(rc == AOS_OK, "注入 LC_LOAD_DYLIB 成功");
    T_CHECK(out != NULL && out_len == len, "输出长度不变（只吃 padding，不搬文件）");
    if (rc == AOS_OK) {
        aos_macho_image_t img2;
        T_CHECK(aos_macho_open(out, out_len, &img2) == AOS_OK, "注入结果可重新解析");
        T_CHECK(img2.ncmds == 3, "ncmds 2 → 3");
        T_CHECK(img2.sizeofcmds == 176u + 56u, "sizeofcmds +56（24+32 对齐 8）");
        T_CHECK(aos_macho_count_injections(&img2, path) == 1, "注入计数 = 1");
        lc_ctx_t c2 = {0, 0};
        aos_macho_foreach_lc(&img2, lc_visitor, &c2);
        T_CHECK(c2.count == 3 && c2.last_cmd == AOS_LC_LOAD_DYLIB, "末条 LC 为 LOAD_DYLIB");
        const uint8_t *nl = out + img.header_end;
        T_CHECK(aos_rd32(nl) == AOS_LC_LOAD_DYLIB, "新命令 cmd 字段正确");
        T_CHECK(aos_rd32(nl + 4) == 56u, "新命令 cmdsize = 56");
        T_CHECK(aos_rd32(nl + 8) == AOS_SIZEOF_DYLIB_COMMAND, "name_off = 24");
        const char *p = aos_dylib_path(nl, aos_rd32(nl + 4));
        T_CHECK(p && !strcmp(p, path), "新 dylib 路径可被读出且完全一致");
        T_CHECK(aos_rd32(out + TFI_SECTION_OFF) == 0x0A05C0DEu,
                "__TEXT 数据区魔数未被搬动");
        T_CHECK(!memcmp(out + TFI_HEADER_END + 56, thin + TFI_HEADER_END + 56,
                        len - TFI_HEADER_END - 56), "padding 之后的全部字节保持不变");

        /* 重复注入：实现只告警不拦截，会再加一条 */
        uint8_t *out2 = NULL; size_t out2_len = 0;
        T_CHECK(aos_macho_inject_dylib(out, out_len, path, AOS_LC_LOAD_DYLIB,
                                       &out2, &out2_len) == AOS_OK, "二次注入返回 OK");
        aos_macho_image_t img3;
        aos_macho_open(out2, out2_len, &img3);
        T_CHECK(aos_macho_count_injections(&img3, path) == 2, "重复注入后计数 = 2");
        aos_free(out2);
        aos_free(out);
    }

    /* ---- 7. weak 注入 ---- */
    uint8_t *wout = NULL; size_t wlen = 0;
    T_CHECK(aos_macho_inject_dylib(thin, len, path, AOS_LC_LOAD_WEAK_DYLIB,
                                   &wout, &wlen) == AOS_OK, "weak 注入成功");
    if (wout) {
        aos_macho_image_t wi;
        aos_macho_open(wout, wlen, &wi);
        T_CHECK(aos_rd32(wout + img.header_end) == AOS_LC_LOAD_WEAK_DYLIB,
                "weak 命令为 LC_LOAD_WEAK_DYLIB");
        T_CHECK(aos_macho_count_injections(&wi, path) == 1, "weak 注入也计入统计");
        aos_free(wout);
    }

    /* ---- 8. 加密包必须拒绝 ---- */
    uint8_t *enc = (uint8_t *)malloc(len);
    memcpy(enc, thin, len);
    uint8_t *mn = enc + AOS_SIZEOF_MACH_HEADER_64 + TFI_SEG_CMDSIZE;
    aos_wr32(mn + 0, AOS_LC_ENCRYPTION_INFO_64);
    aos_wr32(mn + 16, 1u);   /* cryptid != 0 */
    aos_macho_image_t ei;
    T_CHECK(aos_macho_open(enc, len, &ei) == AOS_OK && ei.is_encrypted == 1,
            "cryptid != 0 被识别为仍加密");
    uint8_t *eo = NULL; size_t eol = 0;
    T_CHECK(aos_macho_inject_dylib(enc, len, path, 0, &eo, &eol) == AOS_ERR_ENCRYPTED,
            "加密包注入被拒绝（先砸壳）");
    aos_free(eo); free(enc);

    /* ---- 9. padding 不足 ---- */
    uint8_t *tight = (uint8_t *)malloc(len);
    memcpy(tight, thin, len);
    aos_wr32(tight + AOS_SIZEOF_MACH_HEADER_64 + AOS_SIZEOF_SEGMENT_COMMAND_64 + 48,
             (uint32_t)TFI_HEADER_END + 8u);   /* 只剩 8 字节空白 */
    uint8_t *to = NULL; size_t tol = 0;
    T_CHECK(aos_macho_inject_dylib(tight, len, path, 0, &to, &tol) == AOS_ERR_NO_SPACE,
            "padding 不足 → NO_SPACE");
    aos_free(to); free(tight);

    /* ---- 10. fat 输入 ---- */
    size_t flen = 0;
    uint8_t *fat = tfi_make_fat(&flen);
    T_CHECK(fat != NULL, "夹具构造 fat 成功");
    if (fat) {
        aos_macho_image_t fi;
        T_CHECK(aos_macho_open(fat, flen, &fi) == AOS_OK && fi.ncmds == 2,
                "fat 自动选中 arm64 slice");
        uint8_t *ex = NULL; size_t exl = 0;
        T_CHECK(aos_macho_extract_arm64(fat, flen, &ex, &exl) == AOS_OK,
                "提取 arm64 slice 成功");
        T_CHECK(ex && exl == len, "提取结果为 thin，长度一致");
        aos_free(ex);
        uint8_t *fo = NULL; size_t fol = 0;
        T_CHECK(aos_macho_inject_dylib(fat, flen, path, 0, &fo, &fol) == AOS_OK,
                "对 fat 输入直接注入成功");
        if (fo) {
            T_CHECK(aos_rd32(fo) == AOS_MH_MAGIC_64, "fat 注入输出为 thin 镜像");
            aos_macho_image_t foi;
            aos_macho_open(fo, fol, &foi);
            T_CHECK(aos_macho_count_injections(&foi, path) == 1, "fat 注入结果含新 dylib");
            aos_free(fo);
        }
        free(fat);
    }

    T_CHECK(strcmp(aos_lc_name(AOS_LC_SEGMENT_64), "未知 Load Command") != 0,
            "Load Command 名称表可用");
    T_CHECK(strstr(aos_status_text(AOS_ERR_ENCRYPTED), "加密") != NULL,
            "错误码文本含中文说明");
    free(thin);
    T_REPORT("test_macho");
}
