# A-OS 兼容层 —— Android 共享库构建（NDK / arm64-v8a）
#
# 用法：
#   cmake -S android -B build-android \
#     -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
#     -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26 -DANDROID_STL=none
#
# 产物 libaos_compat.so 会被 NativeActivity 直接 dlopen。
# 许可证：GPL-3.0-only
cmake_minimum_required(VERSION 3.16)
project(aos_compat VERSION 0.3.0 LANGUAGES C ASM)

set(AOS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")

# 与桌面端共用同一套 C 源码和同一组 aarch64 汇编跳板，
# 只是这里编成 SHARED 而不是静态库 + 可执行文件。
add_library(aos_compat SHARED
  ${AOS_ROOT}/src/aos_common.c
  ${AOS_ROOT}/src/macho.c
  ${AOS_ROOT}/src/inject.c
  ${AOS_ROOT}/src/jit_arm64.c
  ${AOS_ROOT}/src/syscall_table.c
  ${AOS_ROOT}/src/syscall_dispatch.c
  ${AOS_ROOT}/src/jailbreak.c
  ${AOS_ROOT}/src/loader.c
  ${AOS_ROOT}/src/exec.c
  ${AOS_ROOT}/src/aarch64/entry.S
  ${AOS_ROOT}/src/aarch64/trampoline.S
  jni/android_bridge.c
)

target_include_directories(aos_compat PRIVATE ${AOS_ROOT}/include)
target_compile_options(aos_compat PRIVATE -Wall -Wextra -O2)
target_compile_definitions(aos_compat PRIVATE AOS_ANDROID_BUILD=1)

# 不加 -fvisibility=hidden：系统需要直接 dlsym 到 ANativeActivity_onCreate，
# 汇编跳板 aos_guest_trap_handler 也保持默认可见，省掉 PLT/可见性的意外。
target_link_libraries(aos_compat PRIVATE log android)

set_target_properties(aos_compat PROPERTIES
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
