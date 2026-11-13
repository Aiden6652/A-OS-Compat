# A-OS 兼容层 —— 构建脚本（注释全中文）
# 许可证：GPL-3.0-only
cmake_minimum_required(VERSION 3.16)
project(A-OS-Compat VERSION 0.2.0 LANGUAGES C ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
add_compile_options(-Wall -Wextra)
# GCC 对固定 1024 字节路径缓冲的 snprintf 拼接会报 -Wformat-truncation，
# 这里所有拼接都已显式检查返回值，属静态分析假阳性，单独关掉这一类。
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  add_compile_options(-Wno-format-truncation)
endif()

# 核心静态库：全部为 C，x86_64 与 aarch64 均可编译
set(AOS_CORE_SOURCES
  src/aos_common.c
  src/macho.c
  src/inject.c
  src/jit_arm64.c
  src/syscall_table.c
  src/syscall_dispatch.c
  src/jailbreak.c
  src/loader.c
  src/exec.c
)
add_library(aos_core STATIC ${AOS_CORE_SOURCES})
target_include_directories(aos_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# ARM64 汇编跳板仅在目标架构为 aarch64 时纳入；x86_64 的汇编器不认这些指令
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
  target_sources(aos_core PRIVATE src/aarch64/entry.S src/aarch64/trampoline.S)
  message(STATUS "目标架构 ARM64：已纳入 entry.S / trampoline.S 汇编跳板")
else()
  message(STATUS "宿主架构 ${CMAKE_SYSTEM_PROCESSOR}：跳过 entry.S，仅验证 C 部分可编译")
endif()

# 命令行工具
add_executable(aos-info   tools/aos-info.c)
add_executable(aos-inject tools/aos-inject.c)
add_executable(aos-run    tools/aos-run.c)
target_link_libraries(aos-info   PRIVATE aos_core)
target_link_libraries(aos-inject PRIVATE aos_core)
target_link_libraries(aos-run    PRIVATE aos_core)

# 单元测试（每台测试都是独立可执行文件，便于 ctest 单独定位失败）
enable_testing()
set(AOS_TESTS test_macho test_jit test_syscall test_jailbreak test_sandbox test_exec)
foreach(t ${AOS_TESTS})
  add_executable(${t} tests/${t}.c)
  target_link_libraries(${t} PRIVATE aos_core)
  target_include_directories(${t} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
  add_test(NAME ${t} COMMAND ${t})
endforeach()
