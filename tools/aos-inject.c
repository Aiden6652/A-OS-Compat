/*
 * A-OS 兼容层 —— dylib 注入工具
 * 用法：aos-inject <输入 Mach-O> <输出 Mach-O> <dylib 路径> [--weak]
 *
 * 只吃 linker 预留的 header padding，不搬动 __TEXT / __LINKEDIT 一字节。
 * 注入后原 LC_CODE_SIGNATURE 必然失效，但宿主 loader 自己就是 dyld，
 * 走自签 trust cache，不校验 AMFI，因此无需重签名。
 *
 * 许可证：GPL-3.0-only
 */
#include "aos_macho.h"
#include "aos_jailbreak.h"
#include <stdlib.h>
#include <string.h>

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

static int write_file(const char *path, const uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return AOS_ERR_IO;
    size_t w = fwrite(buf, 1, len, f);
    if (fclose(f) != 0) return AOS_ERR_IO;
    return w == len ? AOS_OK : AOS_ERR_IO;
}

static void usage(const char *prog) {
    printf("用法：%s <输入 Mach-O> <输出 Mach-O> <dylib 路径> [--weak]\n", prog);
    printf("  --weak  改用 LC_LOAD_WEAK_DYLIB（库缺失时不致命）\n");
    printf("  示例：%s Payload/App.decrypted out.decrypted \\\n"
           "           @executable_path/AOSTweak.dylib\n", prog);
}

int main(int argc, char **argv) {
    const char *in = NULL, *out_path = NULL, *dylib = NULL;
    int weak = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--weak")) { weak = 1; continue; }
        if (!in) in = argv[i];
        else if (!out_path) out_path = argv[i];
        else if (!dylib) dylib = argv[i];
        else { usage(argv[0]); return 2; }
    }
    if (!in || !out_path || !dylib) { usage(argv[0]); return 2; }

    size_t len = 0;
    uint8_t *buf = read_file(in, &len);
    if (!buf) { AOS_LOG_FAIL("读不了输入文件：%s", in); return 1; }

    aos_macho_image_t img;
    int rc = aos_macho_open(buf, len, &img);
    if (rc != AOS_OK) {
        AOS_LOG_FAIL("输入不是可处理的 arm64 砸壳包：%s", aos_status_text(rc));
        aos_free(buf); return 1;
    }

    printf("════ A-OS 兼容层 · dylib 注入 ════\n");
    printf("  输入       : %s（%zu 字节）\n", in, len);
    printf("  架构       : %s\n",
           img.is_arm64e ? "arm64e（含 PAC）" : "arm64（无 PAC）");
    printf("  脱壳状态   : %s\n",
           img.is_encrypted ? "仍带 FairPlay 加密（会被拒绝）" : "已脱壳");
    printf("  注入目标   : %s（%s）\n", dylib,
           weak ? "LC_LOAD_WEAK_DYLIB" : "LC_LOAD_DYLIB");

    uint8_t *out = NULL; size_t out_len = 0;
    rc = aos_macho_inject_dylib(buf, len, dylib,
                                weak ? AOS_LC_LOAD_WEAK_DYLIB : AOS_LC_LOAD_DYLIB,
                                &out, &out_len);
    if (rc != AOS_OK) {
        AOS_LOG_FAIL("注入失败：%s", aos_status_text(rc));
        aos_free(buf); return 1;
    }
    rc = write_file(out_path, out, out_len);
    aos_free(out);
    aos_free(buf);
    if (rc != AOS_OK) { AOS_LOG_FAIL("写不出输出文件：%s", out_path); return 1; }

    printf("  输出       : %s（%zu 字节）\n", out_path, out_len);
    printf("──── 越狱环境说明 ────\n");
    aos_jbenv_t env;
    if (aos_jbenv_init(&env, NULL) == AOS_OK) {
        printf("  原 LC_CODE_SIGNATURE 失效后由宿主 loader 自签 trust cache 兜底，\n");
        printf("  我们自己就是 dyld，不校验 AMFI，因此【无需重签名】。\n");
        printf("  rootless 前缀：%s\n", env.jb_root);
    }
    printf("════ 注入完毕 ════\n");
    return 0;
}
