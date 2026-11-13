# A-OS 兼容层

> 在 **ARM64 安卓手机**上，原生虚拟化运行 **iOS 砸壳 IPA**（已脱 FairPlay 加密），自带 rootless 越狱环境，支持 dylib 注入。
>
> **一句话定调：运行部分是虚拟化（硬件原生执行 guest 的 arm64 机器码），只有转译部分用 JIT 加速。不做指令级转译、不模拟整套 iOS、不上 QEMU。**

| 项目 | 值 |
| --- | --- |
| 版本 | `0.1.0`（可编译、可测试的核心骨架） |
| 许可证 | **GPL-3.0-only**（仅 GPLv3，不含 "or later"） |
| 目标架构 | `aarch64`（安卓宿主） / guest 为普通 `arm64` |
| 文档 | 本文件为中文默认 · [English](README.en.md) · [한국어](README.ko.md) |

---

## 一、开局裁决：扒 UniXNU 的 XNU 内核魔改，还是写用户态 Syscall 兼容层？

**军师裁决：走用户态兼容层，别去扒内核。** 原地起立，理由摆齐：

| 维度 | 扒 UniXNU / 魔改 XNU 内核 | **用户态 Darwin 兼容层（本方案）** |
| --- | --- | --- |
| 内核前提 | 要替换安卓的 Linux 内核，或把 XNU 塞进 KVM | 安卓已有 Linux 内核，直接复用 |
| 驱动 | 要重写整套 Apple 板级驱动（大量专有、无源码） | 只用 Linux 已有的 `mmap`/`mprotect`/`prctl`/`signalfd` |
| 虚拟化 | 普通手机 `/dev/kvm` 常被厂商锁死；上 pKVM 又容易踩**嵌套虚拟化**这个性能黑洞 | 不需要 KVM，用 **Syscall User Dispatch** 按代码地址区间隔离 |
| 页表 | XNU 16KiB 页要魔改页表 | iOS 16KiB 是安卓 4KiB 的整数倍，`mprotect` 天然对齐，白捡 |
| 可调试性 | 内核 panic 就全瞎 | 全在用户态，gdb / 单元测试随便上 |
| 结论 | 骂娘：工作量等于重写一个 iOS 内核，且和安卓底层打架 | **✅ 采纳** |

> XNU 内核移植（UniXNU）的价值在于「让 XNU 跑在别的板子上」；而我们的板子已经有 Linux 了，真正缺的只是 **Darwin ABI 边界**。所以只补边界，不动内核。

---

## 二、三条铁律（总架构师定调，别再跑偏）

1. **不模拟整套 iOS。** 不加载 `dyld_shared_cache`（受版权保护、且是 `arm64e`/PAC），走 touchHLE 验证过的**高层仿真（HLE）**路线：只实现 App 真正调用到的框架 API。
2. **不做指令转译。** 安卓手机本身就是 ARM64，IPA 里的 `arm64` 机器码由硬件**直接原生执行**，没有翻译、没有解释、没有任何 QEMU。
3. **转译部分才用 JIT 加速，运行部分是虚拟化。** JIT 只负责把 XNU ABI 边界（`svc #0x80` / Mach trap / ObjC 消息桥 / 高频框架调用）在运行时编译成宿主可直接跳的 trampoline；冷路径走 SUD 拦截，热点把 guest 代码页里的 `svc #0x80` 就地改成 `b <stub>`，之后连信号都不进。

**为什么能这么便宜**：iOS 上绝大部分 App 是普通 `arm64` 而不是 `arm64e`，**没有 PAC**，函数序言不带 `PACIASP`/`AUTIASP`。因此 hook 与 trampoline 用 4 字节 `b`/`br` 直接覆盖即可，不用伺候指针签名。系统库（arm64e）我们本来就不加载。

---

## 三、架构链路

```
┌───────────────────────── 安卓用户态进程 ─────────────────────────┐
│                                                                  │
│  ┌────────────┐   Mach-O 解析 / header padding 注入 dylib         │
│  │ aos-inject │──────────────────────────────┐                   │
│  └────────────┘                              ▼                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ 宿主 loader / 自制 dyld                                     │  │
│  │  · 按 segment 相对偏移 reserve + MAP_FIXED，W^X（R-X / RW-） │  │
│  │  · 自签 trust cache（我们就是签名裁决者，无需 AMFI 绕过）    │  │
│  │  · rootless 越狱环境：/var/jb + TweakInject + pspawn         │  │
│  └───────────────┬────────────────────────────────────────────┘  │
│                  │ br 到 guest 入口（aarch64/entry.S）             │
│                  ▼                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ guest：IPA 自身 arm64 机器码 —— 硬件原生执行，零转译         │  │
│  │   svc #0x80 / Mach trap 命中 guest 代码地址区间              │  │
│  └───────────────┬────────────────────────────────────────────┘  │
│                  │ Syscall User Dispatch（按地址区间拦截）         │
│       ┌──────────┴───────────┐                                    │
│       ▼                      ▼                                    │
│  冷路径：SIGSYS        热路径：JIT 把 svc 改成 b <trampoline>      │
│  查表→转发/模拟          直接跳宿主实现（不再进内核）               │
│       └──────────┬───────────┘                                    │
│                  ▼                                                  │
│  XNU→Linux 转译表：调用号 x16→x8、svc #0x80→#0、errno 约定、      │
│  open→openat(AT_FDCWD)、Mach IPC→XPC 桥                           │
│                  │                                                  │
│                  ▼                                                  │
│  HLE 框架桩：Foundation / UIKit / CoreGraphics / ObjC Runtime /    │
│  Metal（AIR→SPIR-V→Turnip/Adreno Vulkan）                         │
└──────────────────────────────────────────────────────────────────┘
```

---

## 四、关键技术点

| 环节 | 做法 | 对应代码 |
| --- | --- | --- |
| **Mach-O 解析** | 纯 C 字节解析，自包含结构定义，不依赖任何 Apple SDK；严格边界校验；支持 thin / fat（自动取普通 arm64 slice）、`LC_DYLD_CHAINED_FIXUPS`、`LC_ENCRYPTION_INFO_64` | `src/macho.c` |
| **dylib 注入** | 只吃 linker 预留的 **header padding**，追加 `LC_LOAD_DYLIB` / `LC_LOAD_WEAK_DYLIB`，改 `ncmds`/`sizeofcmds`；**不搬动 __TEXT / __LINKEDIT 一字节**；拒绝未脱壳包 | `src/inject.c` |
| **JIT 发射器** | 运行时生成 aarch64 机器码：`movz/movk` 装载 64 位立即数 + `br`、XNU 调用桩、原函数重定位跳板、`svc→b` 热补丁、`mmap` + `mprotect` 的 W^X 可执行页。**所有编码均由 `clang --target=aarch64-linux-gnu` 反汇编核对** | `src/jit_arm64.c` |
| **Syscall 拦截** | `PR_SET_SYSCALL_USER_DISPATCH`（Linux 5.11+）按 **guest 代码地址区间**拦截，宿主 bionic/libc 零损耗直通；切人格只改一个用户态 selector 字节；无权限时退化为 seccomp SIGSYS | `src/syscall_dispatch.c` |
| **ABI 转译** | XNU：调用号在 `x16`、`svc #0x80`、carry + `x0=errno`；Linux：号在 `x8`、`svc #0`、`x0=-errno`。BSD 调用号自成一套，Mach trap 是负数，一律用户态模拟 | `src/syscall_table.c` |
| **自带越狱环境** | 我们自己就是 loader，**根本不存在需要绕过的 AMFI**；只复刻用户态可见语义：`/var/jb` rootless 布局、`DYLD_INSERT_LIBRARIES` + TweakInject plist Filter、pspawn 子进程继承、自签 trust cache、越狱检测一致应答 | `src/jailbreak.c` |
| **沙盒** | `NSHomeDirectory()` / Documents / Library / Caches / tmp 重定向到安卓 app 私有目录；含 `..` 的逃逸直接拒绝；`/var/jb` 映射回越狱根 | `src/loader.c` |
| **图形** | 不碰 Apple 私有库；Metal → AIR → SPIR-V → Turnip/Adreno Vulkan 前端登记，目标先渲染出第一帧 UI | `src/loader.c` |
| **上下文切换** | aarch64 汇编跳板：保存 callee-saved → 切 guest 栈 → `br x0` 原生执行；因普通 arm64 无 PAC，不发射 `paciasp`/`autiasp` | `src/aarch64/entry.S` |

### 避坑指南落实情况

- **防性能黑洞**：不用 KVM、不用嵌套虚拟化；SUD 冷路径 + JIT 热补丁，宿主 syscall 零拦截。
- **防内存溢出**：安卓 LMK 与 iOS jetsam 语义不同——当前在用户态自管映射，进程优先级拦截列入 M4。
- **防图形崩溃**：走 Metal→Vulkan 转译前端（DXVK 同类思路），先求第一帧。

---

## 五、目录结构

```
A-OS-Compat/
├── include/            公共头文件（自包含，无 Apple SDK 依赖）
├── src/
│   ├── macho.c          Mach-O 解析
│   ├── inject.c         dylib 注入
│   ├── jit_arm64.c      ARM64 JIT 指令发射器
│   ├── syscall_table.c  XNU → Linux 转译表
│   ├── syscall_dispatch.c Syscall User Dispatch 拦截层
│   ├── jailbreak.c      rootless 越狱环境
│   ├── loader.c         加载器 / 沙盒 / HLE 桩表
│   ├── aos_common.c     公共实现
│   └── aarch64/entry.S  ARM64 上下文切换汇编跳板
├── tools/
│   ├── aos-info.c       砸壳包审查工具
│   └── aos-inject.c     dylib 注入工具
├── tests/               5 个测试可执行文件，共 186 项断言
├── .github/workflows/   全中文的 GitHub Actions 工作流
├── aarch64-toolchain.cmake   aarch64 交叉编译工具链
├── CMakeLists.txt
├── LICENSE              GPLv3 全文
├── README.md            中文（默认）
├── README.en.md         英文
└── README.ko.md         韩文
```

---

## 六、构建与测试

### 本机（x86_64 / aarch64 均可）

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
cd build && ctest --output-on-failure
```

x86_64 上会跳过 `entry.S` 汇编（只验证 C 部分可编译），aarch64 上自动纳入。当前 CI 结果：**5 个测试全通过，186 项断言零失败，编译零警告**。

### aarch64 交叉编译（GitHub Actions 同款）

```bash
sudo apt-get install -y gcc-aarch64-linux-gnu
cmake -S . -B build-a64 -DCMAKE_TOOLCHAIN_FILE=aarch64-toolchain.cmake
cmake --build build-a64 -j$(nproc)
file build-a64/aos-info     # ELF 64-bit LSBpie executable, ARM aarch64
```

交叉产物只构建、不运行（宿主跑不了）。工具链会自动把 `src/aarch64/entry.S` 纳入静态库。

---

## 七、工具用法

```bash
# 审查一个砸壳 Mach-O：架构 / 是否脱壳 / 链式修正 / header 可用空白 / 全部 Load Commands
./build/aos-info Payload/App.decrypted

# 注入 dylib（只改 header padding，输出长度不变）
./build/aos-inject Payload/App.decrypted App.injected \
    @executable_path/AOSTweak.dylib

# 弱依赖版本（库缺失时不致命）
./build/aos-inject Payload/App.decrypted App.injected \
    /var/jb/usr/lib/TweakInject/Foo.dylib --weak
```

注入后原 `LC_CODE_SIGNATURE` 必然失效——但**宿主 loader 自己就是 dyld，走自签 trust cache，不校验 AMFI，因此无需重签名**。这一点和真机越狱要搞 CoreTrust 注入 / PPL bypass 完全不同：裁决权在我们手里，压根没有 AMFI 需要绕过。

若 header padding 不够，工具会报错提示重链时加 `-headerpad_max_install_names`——这是能救的，别硬搬文件。

---

## 八、诚实的能力边界（别吹牛，兄弟）

**当前 0.1.0 是可编译、可测试、可注入的核心骨架，还跑不通完整 App UI。** 已经落地的：

- ✅ Mach-O 解析 / fat 提取 / dylib 注入（含加密包拒绝、padding 不足检测）
- ✅ ARM64 JIT 发射器（编码逐条反汇编核对）+ W^X 可执行页
- ✅ XNU→Linux syscall 转译表（40 条，含参数重写与 Mach trap 模拟）
- ✅ Syscall User Dispatch 拦截层（aarch64 实机路径 + CI 逻辑桩）
- ✅ rootless 越狱环境（目录树 / trust cache / tweak Filter / pspawn / 越狱检测）
- ✅ 沙盒路径映射、HLE 框架桩登记、加载器映射与 chained fixups 校验
- ✅ 186 项单元测试 + x86_64 自测 + aarch64 交叉编译的 CI

**尚未实现（后续里程碑）**：

- ⬜ `LC_DYLD_CHAINED_FIXUPS` 的完整 bind/opcode 解释（目前只做 rebase 规模校验）
- ⬜ `objc_msgSend` 的完整汇编分发与 SUD 的 SIGSYS 信号处理器接线
- ⬜ Foundation / UIKit 全量控件、Metal 全量管线、XPC/Mach IPC 桥
- ⬜ 真机上的 LMK 进程优先级拦截与冷/热路径性能调优

### 路线图

| 里程碑 | 目标 |
| --- | --- |
| M1 ✅ | 可编译可测试骨架 + 注入工具 + 三语文档 + 全中文 CI |
| M2 | chained fixups 完整 rebase/bind、objc_msgSend 分发、SUD 信号接线 |
| M3 | HLE 最小集 → **渲染出第一帧 UI**；Metal→Vulkan 前端打通 |
| M4 | 真机（root / pKVM 可用设备）性能调优、LMK 拦截 |

---

## 九、许可证与声明

本项目采用 **GPL-3.0-only**（GNU General Public License v3.0 only，不含 "or later"），全文见 [LICENSE](LICENSE)。任何衍生作品必须以相同许可证开源。

本项目仅用于**对本人合法持有、已自行脱壳的 IPA 做技术研究**。请自行遵守所在地区法律与应用许可协议；作者不对使用方式负责。项目不包含、也不分发任何 Apple 私有框架、系统库或受版权保护的二进制。

---

> 军师按：内核不用扒，PAC 不用管，AMFI 不用绕。硬件同源这一条，就是整个方案最大的便宜。
