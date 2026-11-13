# A-OS 兼容层 —— aarch64 交叉编译工具链（GitHub Actions 使用）
# 许可证：GPL-3.0-only
# 说明：只做构建、不运行测试（交叉产物无法在 x86_64 宿主上执行）。
set(CMAKE_SYSTEM_NAME      Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_C_COMPILER       aarch64-linux-gnu-gcc)
set(CMAKE_ASM_COMPILER     aarch64-linux-gnu-gcc)
# 避免 CMake 在探测编译器时尝试链接可执行文件（交叉环境无运行时库）
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
