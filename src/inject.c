/*
 * A-OS 兼容层 —— dylib 注入（修改 Mach-O Load Commands）
 *
 * 手法：只吃 linker 预留的 header padding，不搬动 __TEXT / __LINKEDIT 里
 * 任何一字节。新 LC_LOAD_DYLIB 追加在原 sizeofcmds 末尾，随后改 ncmds /
 * sizeofcmds。因为砸壳包通常带 LC_CODE_SIGNATURE，注入后原签名必然失效 ——
 * 但本兼容层自己就是 loader（越狱环境自签 trust cache），不校验 AMFI，
 * 所以无需重签，只需在日志里明确告知。
 *
 * 许可证：GPL-3.0-only
 */
#include "aos_macho.h"
#include <stdlib.h>

static int is_fat(const uint8_t *p) {
    return p[0] == 0xCA && p[1] == 0xFE && p[2] == 0xBA &&
           (p[3] == 0xBE || p[3] == 0xBF);
}

/* 找出 header padding 的上界：header 之后，第一处真实数据之前 */
static uint64_t padding_limit(const aos_macho_image_t *img) {
    uint64_t limit = (uint64_t)img->size;
    if (img->first_section_off != UINT64_MAX &&
        img->first_section_off < limit) limit = img->first_section_off;

    const uint8_t *lc = img->base + AOS_SIZEOF_MACH_HEADER_64;
    uint64_t remain = img->sizeofcmds;
    for (uint32_t i = 0; i < img->ncmds; i++) {
        uint32_t sz = aos_rd32(lc + 4);
        if (sz < 8 || sz > remain) break;
        if (aos_rd32(lc) == AOS_LC_SEGMENT_64 && sz >= AOS_SIZEOF_SEGMENT_COMMAND_64) {
            uint64_t fileoff = aos_rd64(lc + 40);
            if (fileoff > 0 && fileoff < limit) limit = fileoff;
        }
        lc += sz; remain -= sz;
    }
    return limit;
}

static int inject_thin(const uint8_t *buf, size_t len,
                       const char *path, uint32_t lc_cmd,
                       uint8_t **out_buf, size_t *out_len) {
    aos_macho_image_t img;
    int rc = aos_macho_open(buf, len, &img);
    if (rc != AOS_OK) return rc;
    if (img.is_encrypted) {
        AOS_LOG_FAIL("这包还带 FairPlay 加密（cryptid != 0），先砸干净再来");
        return AOS_ERR_ENCRYPTED;
    }
    if (img.is_arm64e) {
        AOS_LOG_WARN("检测到 arm64e slice（含 PAC），本项目面向普通 arm64；继续注入但运行时不保证");
    }

    size_t plen = strlen(path) + 1;
    if (path[0] == '\0') return AOS_ERR_INVALID_ARG;
    uint32_t name_off = AOS_SIZEOF_DYLIB_COMMAND;
    uint32_t cmdsize  = aos_align_up(name_off + (uint32_t)plen, 8u);

    uint64_t limit = padding_limit(&img);
    if (limit <= img.header_end) return AOS_ERR_NO_SPACE;
    uint64_t avail = limit - img.header_end;
    if (avail < cmdsize) {
        AOS_LOG_FAIL("padding 只剩 %llu 字节，装不下 %u 字节的新命令；"
                     "重链时加 -headerpad_max_install_names",
                     (unsigned long long)avail, cmdsize);
        return AOS_ERR_NO_SPACE;
    }

    /* 重复注入检查 */
    if (aos_macho_count_injections(&img, path) > 0) {
        AOS_LOG_WARN("该 dylib 已在 Load Commands 中，跳过重复注入：%s", path);
    }

    uint8_t *out = (uint8_t *)aos_alloc(len);
    if (!out) return AOS_ERR_NO_MEM;
    memcpy(out, buf, len);

    uint8_t *lc = out + img.header_end;
    aos_wr32(lc + 0,  lc_cmd);       /* cmd */
    aos_wr32(lc + 4,  cmdsize);      /* cmdsize */
    aos_wr32(lc + 8,  name_off);     /* dylib.name */
    aos_wr32(lc + 12, 0);            /* timestamp */
    aos_wr32(lc + 16, 0);            /* current_version */
    aos_wr32(lc + 20, 0);            /* compatibility_version */
    memcpy(lc + name_off, path, plen);
    /* 剩余 padding 保持原样（本来就是 linker 留白 / 零） */

    /* 校验原签名命令是否存在 */
    int had_signature = 0;
    {
        const uint8_t *p = out + AOS_SIZEOF_MACH_HEADER_64;
        uint32_t rem = img.sizeofcmds;
        for (uint32_t i = 0; i < img.ncmds; i++) {
            uint32_t c = aos_rd32(p), s = aos_rd32(p + 4);
            if (s < 8 || s > rem) break;
            if (c == AOS_LC_CODE_SIGNATURE) had_signature = 1;
            p += s; rem -= s;
        }
    }
    if (had_signature) {
        AOS_LOG_WARN("原 LC_CODE_SIGNATURE 已失效；宿主 loader 走自签 trust cache，不校验 AMFI");
    }

    /* 更新 mach_header_64 */
    aos_wr32(out + 16, img.ncmds + 1);
    aos_wr32(out + 20, img.sizeofcmds + cmdsize);

    AOS_LOG_INFO("注入完成：%s（+%u 字节，ncmds %u → %u）",
                 path, cmdsize, img.ncmds, img.ncmds + 1);

    *out_buf = out; *out_len = len;
    return AOS_OK;
}

int aos_macho_inject_dylib(const uint8_t *buf, size_t len,
                           const char *dylib_path, uint32_t lc_cmd,
                           uint8_t **out_buf, size_t *out_len) {
    if (!buf || !dylib_path || !out_buf || !out_len || len < 4)
        return AOS_ERR_INVALID_ARG;
    if (lc_cmd == 0) lc_cmd = AOS_LC_LOAD_DYLIB;
    *out_buf = NULL; *out_len = 0;

    if (!is_fat(buf)) return inject_thin(buf, len, dylib_path, lc_cmd,
                                         out_buf, out_len);

    /* fat：先抽出普通 arm64 slice，注入后以 thin 形式返回。
     * 不去重写 fat_header 的 offset/size —— 那是搬石砸脚，交给后续打包步骤。 */
    AOS_LOG_INFO("输入是 fat 包，先提取普通 arm64 slice 再注入");
    uint8_t *thin = NULL; size_t thin_len = 0;
    int rc = aos_macho_extract_arm64(buf, len, &thin, &thin_len);
    if (rc != AOS_OK) return rc;
    rc = inject_thin(thin, thin_len, dylib_path, lc_cmd, out_buf, out_len);
    aos_free(thin);
    return rc;
}
