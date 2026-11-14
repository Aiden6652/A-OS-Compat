A-OS 兼容层 · APK 使用说明
============================

这个 APK 是纯 native 应用（NativeActivity，无 Java 代码），装上后打开即可在
logcat 里看到执行闭环的输出：

    adb logcat -s A-OS:V A-OS-GUEST:V

启动时会依次做这几件事：
  1. 在 App 私有目录建 rootless 越狱环境（/var/jb 布局、自签 trust cache、
     TweakInject plist、DYLD_INSERT_LIBRARIES、越狱检测应答）；
  2. 加载内置的两套真实 arm64 砸壳样本 Mach-O；
  3. 扫描 __TEXT 里的 svc #0x80，用 JIT 就地改成 b <专属跳板>；
  4. 硬件原生执行 guest 机器码；XNU syscall 经宿主分派器真转发到 Linux；
  5. 在 ANativeWindow 上直接提交第一帧画面。

换成你自己的砸壳包
------------------
把你脱壳后的 Mach-O 可执行文件（不是整个 .ipa 压缩包）命名为
payload.decrypted 放进本 assets 目录，再重新执行 android/build-apk.sh
重新打包签名即可。App 会优先加载 payload.decrypted，找不到才回退内置样本。

注意（0.3.0 的诚实边界）：当前只跑通 syscall 级闭环，还没有 dyld 符号绑定、
objc_msgSend 分发、UIKit/Metal 管线。所以带框架调用的真实 App 会在第一次
取不到符号时停下；不带 Objective-C 运行时依赖的纯 C / 汇编 Mach-O 能完整跑。

日志输出：guest 的 write(1, ...) 会同时转发到 Linux stdout 和 logcat
（tag = A-OS-GUEST），因为 Android App 的 stdout 默认不可见。

许可证：GPL-3.0-only
