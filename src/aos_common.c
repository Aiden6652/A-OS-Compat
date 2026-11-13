/*
 * A-OS 兼容层 —— 公共实现
 * 许可证：GPL-3.0-only
 */
#include "aos_common.h"
#include <stdlib.h>

const char *aos_status_text(int rc) {
    switch (rc) {
        case AOS_OK:              return "成功";
        case AOS_ERR_INVALID_ARG: return "参数非法";
        case AOS_ERR_BAD_MAGIC:   return "不是可识别的 Mach-O 魔数";
        case AOS_ERR_BAD_FORMAT:  return "结构损坏或越界";
        case AOS_ERR_NO_SPACE:    return "header padding 不足，塞不下新的 Load Command";
        case AOS_ERR_ENCRYPTED:   return "仍是 FairPlay 加密包，砸壳没砸干净";
        case AOS_ERR_UNSUPPORTED: return "暂不支持该镜像类型";
        case AOS_ERR_NO_MEM:      return "内存分配失败";
        case AOS_ERR_IO:          return "文件读写失败";
        case AOS_ERR_NOT_FOUND:   return "未找到";
        default:                  return "未知错误";
    }
}

void *aos_alloc(size_t n) {
    void *p = calloc(1, n ? n : 1);
    return p;
}

void aos_free(void *p) {
    free(p);
}
