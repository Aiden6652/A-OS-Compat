#!/usr/bin/env bash
# ============================================================================
# A-OS 兼容层 —— 一键产出可安装的 Android APK（全程中文）
#
# 这条链路是之前缺的那一段：NDK 编 libaos_compat.so → aapt2 打包 →
# zipalign 对齐 → apksigner v1+v2+v3 签名。桌面端 CMake 产的是 Linux ELF，
# 装不进手机，只有走这里才会得到真正的 .apk。
#
# 依赖：
#   · Android SDK（build-tools 任意版本 + platforms/android-3x）
#   · Android NDK（r25 及以上，需 aarch64 clang）
#   · JDK（keytool / apksigner 需要 java）
#   · cmake、zip
#
# 可用环境变量覆盖：ANDROID_HOME、ANDROID_NDK_HOME、JAVA_HOME
#
# 用法：./android/build-apk.sh
# 产物：仓库根目录 A-OS-Compat-arm64-v8a-debug.apk
# 许可证：GPL-3.0-only
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AND_DIR="$ROOT/android"
WORK="$ROOT/build-android"
OUT="$ROOT/A-OS-Compat-arm64-v8a-debug.apk"

# ---------- 环境探测 ----------
ANDROID_HOME="${ANDROID_HOME:-/opt/android-sdk}"
if [ ! -d "$ANDROID_HOME" ]; then
  echo "[军师·骂娘] 找不到 ANDROID_HOME：$ANDROID_HOME"; exit 1
fi

if [ -n "${ANDROID_NDK_HOME:-}" ] && [ -f "$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" ]; then
  NDK="$ANDROID_NDK_HOME"
else
  NDK="$(ls -d "$ANDROID_HOME"/ndk/*/ 2>/dev/null | sort -V | tail -1 || true)"
  NDK="${NDK%/}"
  if [ -z "$NDK" ] && [ -f /opt/android-ndk/r27c/build/cmake/android.toolchain.cmake ]; then
    NDK=/opt/android-ndk/r27c
  fi
fi
if [ -z "$NDK" ] || [ ! -f "$NDK/build/cmake/android.toolchain.cmake" ]; then
  echo "[军师·骂娘] 找不到 Android NDK，请先装：sdkmanager --install \"ndk;27.0.12077973\""
  exit 1
fi

BT="$(ls -d "$ANDROID_HOME"/build-tools/*/ 2>/dev/null | sort -V | tail -1 || true)"
BT="${BT%/}"
PLATFORM="$(ls -d "$ANDROID_HOME"/platforms/android-*/ 2>/dev/null | sort -V | tail -1 || true)"
PLATFORM="${PLATFORM%/}"
if [ -z "$BT" ] || [ -z "$PLATFORM" ]; then
  echo "[军师·骂娘] 缺 build-tools 或 platform，先跑 sdkmanager --install \"platforms;android-35\" \"build-tools;35.0.0\""
  exit 1
fi

AAPT2="$BT/aapt2"
ZIPALIGN="$BT/zipalign"
APKSIGNER="$BT/apksigner"
ANDROID_JAR="$PLATFORM/android.jar"
API_LEVEL="$(basename "$PLATFORM" | sed 's/android-//')"

if [ -z "${JAVA_HOME:-}" ]; then
  JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")"
fi
export PATH="$JAVA_HOME/bin:$PATH"

echo "════════════════════════════════════════════════════"
echo " A-OS 兼容层 · APK 打包"
echo "════════════════════════════════════════════════════"
echo "  NDK         : $NDK"
echo "  build-tools : $BT"
echo "  platform    : $PLATFORM (API $API_LEVEL)"
echo "  JDK         : $JAVA_HOME"

# ---------- 1. NDK 交叉编译 arm64-v8a 共享库 ----------
echo ""
echo "──── [1/5] NDK 编译 libaos_compat.so ────"
mkdir -p "$WORK"
cmake -S "$AND_DIR" -B "$WORK/cmake" \
  -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-26 \
  -DANDROID_STL=none \
  -DCMAKE_BUILD_TYPE=Release > "$WORK/cmake_cfg.log" 2>&1 || {
    tail -30 "$WORK/cmake_cfg.log"; exit 1;
  }
cmake --build "$WORK/cmake" -j4
SO="$WORK/cmake/libaos_compat.so"
test -f "$SO" || { echo "[军师·骂娘] 没产出 .so"; exit 1; }
file "$SO"
echo "  导出符号核对："
NM="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-nm"
if [ -x "$NM" ]; then
  "$NM" -D "$SO" 2>/dev/null \
    | grep -E "ANativeActivity_onCreate|aos_guest_trap_handler|aos_exec_run" || true
else
  echo "  （llvm-nm 不可用，跳过）"
fi

# ---------- 2. aapt2 生成基础 APK ----------
echo ""
echo "──── [2/5] aapt2 编译清单与资源 ────"
rm -rf "$WORK/apk" && mkdir -p "$WORK/apk/lib/arm64-v8a"
cp "$SO" "$WORK/apk/lib/arm64-v8a/libaos_compat.so"
UNSIGNED="$WORK/app-unsigned.apk"
rm -f "$UNSIGNED"
"$AAPT2" link -o "$UNSIGNED" \
  -I "$ANDROID_JAR" \
  --manifest "$AND_DIR/app/src/main/AndroidManifest.xml" \
  -A "$AND_DIR/app/src/main/assets" \
  --min-sdk-version 26 --target-sdk-version "$API_LEVEL" \
  --version-code 3 --version-name 0.3.0
echo "  基础 APK: $(stat -c %s "$UNSIGNED") 字节"

# ---------- 3. 塞入 native 库 ----------
echo ""
echo "──── [3/5] 塞入 lib/arm64-v8a/libaos_compat.so ────"
(cd "$WORK/apk" && zip -q -r "$UNSIGNED" lib)
unzip -l "$UNSIGNED" | grep -E "libaos_compat|AndroidManifest|assets/"

# ---------- 4. zipalign 对齐 ----------
echo ""
echo "──── [4/5] zipalign 4 字节对齐 ────"
ALIGNED="$WORK/app-aligned.apk"
"$ZIPALIGN" -f -p 4 "$UNSIGNED" "$ALIGNED"
"$ZIPALIGN" -c -p 4 "$ALIGNED" && echo "  对齐校验通过"

# ---------- 5. 自签 debug keystore + apksigner ----------
echo ""
echo "──── [5/5] v1+v2+v3 签名 ────"
KS="$WORK/debug.keystore"
if [ ! -f "$KS" ]; then
  keytool -genkeypair -v -keystore "$KS" \
    -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass android -keypass android \
    -dname "CN=A-OS Debug, OU=A-OS, O=A-OS, L=Shenzhen, ST=Guangdong, C=CN" \
    > /dev/null 2>&1
  echo "  已生成自签 debug keystore"
fi
rm -f "$OUT"
"$APKSIGNER" sign \
  --ks "$KS" --ks-pass pass:android --key-pass pass:android \
  --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \
  --out "$OUT" "$ALIGNED"
"$APKSIGNER" verify --verbose "$OUT" | sed 's/^/  /'

# ---------- 收尾报告 ----------
echo ""
echo "════════════════════════════════════════════════════"
echo " 成品：$OUT"
echo " 大小：$(stat -c %s "$OUT") 字节"
echo "════════════════════════════════════════════════════"
echo ""
echo "──── APK 信息 ────"
"$AAPT2" dump badging "$OUT" 2>&1 \
  | grep -E "^package:|sdkVersion|targetSdkVersion|application-label|native-code|launchable-activity" \
  | sed 's/^/  /' || true
echo ""
echo "安装：adb install -r $OUT"
echo "看日志：adb logcat -s A-OS:V A-OS-GUEST:V"
echo "（debug 自签名，装之前系统可能提示「未知来源」，允许即可）"
