/*
 * A-OS 兼容层 —— Mach-O 信息查看器
 * 用法：aos-info <砸壳 Mach-O 路径>
 * 许可证：GPL-3.0-only
 */
#include "aos_macho.h"
#include "aos_jailbreak.h"
#include "aos_loader.h"
#include "aos_syscall.h"
#include <stdlib.h>

typedef struct { int total; int dylibs; } lc_stat_t;

static int visitor(uint32_t cmd, uint32_t cmdsize, const uint8_t *lc, void *ctx) {
    lc_stat_t *s = (lc_stat_t *)ctx;
    s->total++;
    printf("  [%02d] %-38s cmdsize=%u", s->total, aos_lc_name(cmd), cmdsize);
    if (cmd == AOS_LC_LOAD_DYLIB || cmd == AOS_LC_LOAD_WEAK_DYLIB ||
        cmd == AOS_LC_ID_DYLIB || cmd == AOS_LC_REEXPORT_DYLIB) {
        const char *p = aos_dylib_path(lc, cmdsize);
        if (p) { printf("  → %s", p); s->dylibs++; }
    }
    printf("\n");
    return AOS_OK;
}

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n <= 0) { fclose(f); return NULL; }
    rewind(f);
    uint8_t *b = (uint8_t *)aos_alloc((size_t)n);
    if (!b) { fclose(f); return NULL; }
    if (fread(b, 1, (size_t)n, f) != (size_t)n) {
        aos_free(b); fclose(f); return NULL;
    }
    fclose(f); *len = (size_t)n; return b;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("用法：%s <砸壳 Mach-O 路径>\n", argv[0]);
        return 2;
    }
    size_t len = 0;
    uint8_t *buf = read_file(argv[1], &len);
    if (!buf) { AOS_LOG_FAIL("读不了文件：%s", argv[1]); return 1; }

    aos_macho_image_t img;
    int rc = aos_macho_open(buf, len, &img);
    if (rc != AOS_OK) {
        AOS_LOG_FAIL("解析失败：%s", aos_status_text(rc));
        aos_free(buf); return 1;
    }

    printf("════ A-OS 兼容层 · 砸壳包审查 ════\n");
    printf("  文件         : %s（%zu 字节）\n", argv[1], len);
    printf("  架构         : %s（cputype=0x%08X, subtype=0x%08X）\n",
           img.is_arm64e ? "arm64e（含 PAC，本项目不碰）" : "arm64（无 PAC）",
           img.cpu_type, img.cpu_subtype);
    printf("  文件类型     : %u   入口偏移: 0x%llx\n",
           img.filetype, (unsigned long long)img.entryoff);
    printf("  __TEXT 首选  : 0x%llx\n", (unsigned long long)img.text_vmaddr);
    printf("  Load Commands: %u 条 / %u 字节\n", img.ncmds, img.sizeofcmds);
    printf("  FairPlay 加密: %s\n", img.is_encrypted ? "仍在（先砸壳！）" : "已脱壳");
    printf("  链式修正     : %s\n", img.has_chained_fixups ? "LC_DYLD_CHAINED_FIXUPS（iOS 15+）" : "经典 fixups");
    printf("  header 空白  : %llu 字节可用（可注入 dylib）\n",
           (unsigned long long)(img.first_section_off == UINT64_MAX
             ? (uint64_t)img.size - img.header_end
             : img.first_section_off - img.header_end));
    printf("──── Load Commands ────\n");
    lc_stat_t st = {0, 0};
    aos_macho_foreach_lc(&img, visitor, &st);
    printf("  合计 %d 条，其中动态库依赖 %d 个\n", st.total, st.dylibs);

    printf("──── 兼容层运行时 ────\n");
    printf("  转译表条目   : %zu（BSD + Mach trap）\n", aos_syscall_table_size());
    printf("  HLE 框架桩   : %zu 个符号\n", aos_hle_stub_count());
    aos_hle_init();

    aos_jbenv_t env;
    if (aos_jbenv_init(&env, NULL) == AOS_OK) {
        printf("  自带越狱环境 : rootless 前缀 %s（自签 trust cache，无需 AMFI 绕过）\n",
               env.jb_root);
    }

    aos_free(buf);
    printf("════ 审查完毕 ════\n");
    return 0;
}
