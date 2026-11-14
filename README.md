# A-OS 兼容层

> 在 **ARM64 安卓手机**上，原生虚拟化运行 **iOS 砸壳 IPA**（已脱 FairPlay 加密），自带 rootless 越狱环境，支持 dylib 注入。
>
> **一句话定调：运行部分是虚拟化（硬件原生执行 guest 的 arm64 机器码），只有转译部分用 JIT 加速。不做指令级转译、不模拟整套 iOS、不上 QEMU。**

| 项目 | 值 |
| --- | --- |
| 版本 | `0.3.0`（执行闭环 + **可安装的 Android APK**：加载 → JIT 预补丁 → 原生执行 → 陷阱转译 → 返回 guest） |
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

### 关于 touchHLE：借壳，不换心

有人问「网上那个能跑 32 位 iOS 的 touchHLE，改一改不就行了？」军师查完官方仓库，四道硬墙：

| 事实 | touchHLE 现状 | 对我们的影响 |
| --- | --- | --- |
| 许可证 | 源码 **MPL-2.0**（只有二进制是 GPLv3-or-later） | 整包搬进 `GPL-3.0-only` 会污染许可证，还带一堆依赖授权 |
| CPU 层 | **dynarmic** 指令级 JIT 重编译（"emulated CPU"） | 恰恰是我们要拆掉的指令转译，与「硬件原生执行」对撞 |
| 架构 | 官方明确 **Never: 64-bit iOS**，只跑 armv7 / iPhone OS 2.x–4.0.x | 不认 arm64 Mach-O，换 CPU 后端等于重写 |
| 语言 | Rust + SDL + OpenGL ES | 本项目纯 C，栈不通 |

**所以不 fork、不拷一行 MPL 代码**（许可证保持纯净的 GPL-3.0-only）。真正借的是它那个「自己实现系统框架」的 **HLE 壳子** —— 这层用户态语义与 CPU 位数无关，正好填我们项目里的框架桩：0.2.0 已把空桩换成真能干活的 C 实现（`NSLog` 真输出、`NSHomeDirectory` 真返回沙盒路径、`CGRectMake` 真构造、`malloc/free` 真转发、ObjC/Metal 返回一致伪句柄），统一由 `aos_hle_invoke()` 分派。

> 顺带一句实用信息：如果你只是想玩老 32 位 iOS 游戏，**直接装 touchHLE 的 AArch64 Android APK 就行**（官方有 Android 版），不用改任何东西。但那是通过 dynarmic 翻译 armv7 指令跑的，跟我们做的 64 位原生虚拟化是两码事。

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

### 已跑通的执行闭环（0.2.0，有实证）

不是纸面设计，`aos-run --selftest` 真把一段 **arm64 机器码**跑完了：

```bash
cmake -S . -B build-a64 -DCMAKE_TOOLCHAIN_FILE=aarch64-toolchain.cmake
cmake --build build-a64 -j$(nproc)
qemu-aarch64-static -L /usr/aarch64-linux-gnu ./build-a64/aos-run --selftest
```

实际输出（节选）：

```
──── 开始执行 guest（硬件原生 arm64 指令）────
A-OS NATIVE OK
──── guest 已返回 ────
  guest 退出码 : 42          ← 样本 1：write 转发 + exit 码传出
  ...
A-OS NATIVE OK
  guest 退出码 : 15          ← 样本 2：write 的返回值被写回 guest 的 x0 并用作 exit 码
两套样本全部通过：write 真转发、返回值写回 x0、陷阱后继续执行、exit 码正确传出。
```

链条是这样闭合的：

1. `aos_exec_map()` 一次性把 guest 镜像与 JIT 桩区 mmap 到**相邻地址**（保证 `b` 的 ±128MB 可达），按 segment 相对偏移 `MAP_FIXED` 风格映射，W^X。
2. `aos_exec_scan_traps()` 扫出可执行段里所有 `svc #0x80`；`aos_exec_patch_all()` 为每个陷阱点生成**专属跳板**（`mov64 x9, 返回地址` + `b <共享桩>`），共享桩 `mov64 x17` + `br` 绝对跳到宿主汇编陷阱桩。跳板用 `b` 不用 `bl`，**绝不碰 `x30`**。
3. guest 里的 `svc #0x80` 被就地改成 `b <跳板>`；**除这几条陷阱指令外，guest 机器码一个字节都没动**，硬件原生执行。
4. `trampoline.S` 的 `aos_guest_trap_handler` 保存现场 → `bl aos_trap_dispatch` → C 分派器查表后**真发 Linux `syscall()`** → 把 `-errno` 转回 XNU 的 `x0=errno + carry 置位` → 恢复现场 → `br x9` 回 guest 继续执行。
5. XNU `exit` 不真杀宿主进程，用 `longjmp` 回 `aos_exec_run()` 交出退出码。

> **关于 qemu**：`qemu-aarch64` 只用于 CI / 本地**验证闭环逻辑**，绝不进入产品运行路径；在真 ARM64 手机上，guest 的 arm64 指令由硬件原生执行，没有任何 qemu、没有任何指令翻译。项目也**不需要 KVM / 嵌套虚拟化 / SUD / seccomp** —— 陷阱点在首次执行前就已是 JIT 桩，等于永远的热路径。`src/syscall_dispatch.c` 的 SUD 层保留为「guest 运行时自生成代码」的可选兜底。

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
| **执行引擎（0.2.0）** | 静态扫描 `svc #0x80` → 每点生成专属 JIT 跳板 → `b` 就地覆盖 → 宿主汇编陷阱桩真转发 Linux syscall → `br` 回 guest；XNU exit 用 longjmp 回宿主 | `src/exec.c` · `src/aarch64/trampoline.S` |
| **HLE 真实现（0.2.0）** | `aos_hle_invoke()` 统一分派：NSLog 真输出、NSHomeDirectory 返回沙盒路径、CGRectMake 真构造、malloc/free 真转发、ObjC/Metal 伪句柄 | `src/loader.c` |

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
│   ├── loader.c         加载器 / 沙盒 / HLE 真实现
│   ├── exec.c           执行引擎：陷阱扫描 / 相邻映射 / JIT 预补丁 / C 分派器
│   ├── aos_common.c     公共实现
│   └── aarch64/
│       ├── entry.S          ARM64 上下文切换汇编跳板
│       └── trampoline.S     宿主陷阱桩（保存现场→转译→写回→br 回 guest）
├── tools/
│   ├── aos-info.c       砸壳包审查工具
│   ├── aos-inject.c     dylib 注入工具
│   └── aos-run.c        运行器（--selftest / 外部镜像 / --emit）
├── tests/               6 个测试可执行文件，共 250 项断言
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

x86_64 上会跳过 `entry.S` / `trampoline.S` 汇编（只验证 C 部分可编译），aarch64 上自动纳入。当前 CI 结果：**6 个测试全通过，250 项断言零失败，编译零警告**。

### 跑通执行闭环（aarch64 实机 / qemu 验证）

```bash
qemu-aarch64-static -L /usr/aarch64-linux-gnu ./build-a64/aos-run --selftest
```

CI 的「交叉编译」任务会自动装 `qemu-user-static` 并跑这一步，逐项校验
`A-OS NATIVE OK`、退出码 `42` 与 `15`、`HLE 实测`、`两套样本全部通过`。
真 ARM64 设备上直接跑 `./aos-run --selftest` 即可，**不需要 qemu**。

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

### 真正把镜像跑起来

```bash
# 两套内置 arm64 样本，验证完整执行闭环
./build/aos-run --selftest

# 加载并执行一个砸壳 Mach-O
./build/aos-run Payload/App.decrypted

# 导出内置样本，供跨架构 / qemu 验证
./build/aos-run --emit /tmp/guest.macho
```

`aos-run` 会建 rootless 越狱环境、初始化 HLE、映射镜像、生成 JIT 跳板，然后
`br` 进 guest 入口。x86_64 上前四步照做、生成结果可校验，但**明确拒绝执行**
aarch64 机器码（返回码 2），绝不在错误架构上乱跳。

---

## 八、诚实的能力边界（别吹牛，兄弟）

**0.2.0 已经能跑通「syscall 级」的完整闭环，但仍然跑不了任意真实 App 的 UI。** 这两句都得说清楚。

已经落地并验证的：

- ✅ Mach-O 解析 / fat 提取 / dylib 注入（含加密包拒绝、padding 不足检测）
- ✅ ARM64 JIT 发射器（编码逐条反汇编核对）+ W^X 可执行页
- ✅ XNU→Linux syscall 转译表（40 条，含参数重写与 Mach trap 模拟）
- ✅ **静态 ABI 边界预补丁**：扫 `svc #0x80` → 每点专属 JIT 跳板 → `b` 就地覆盖，guest 其余机器码一字节不动
- ✅ **宿主汇编陷阱桩**：真发 Linux `syscall()`、错误约定转换、结果写回 `x0` 后 `br` 回 guest
- ✅ **两套真实 arm64 样本跑通**：write 输出、返回值写回 x0、陷阱后继续执行、exit 码传出（42 / 15）
- ✅ HLE 框架**真实现**（不再是空桩）+ `aos_hle_invoke()` 统一分派
- ✅ rootless 越狱环境（目录树 / trust cache / tweak Filter / pspawn / 越狱检测）
- ✅ 沙盒路径映射、加载器映射与 chained fixups 校验
- ✅ 250 项单元测试 + x86_64 自测 + aarch64 交叉编译 + qemu 执行闭环的 CI

**尚未实现（后续里程碑）**：

- ⬜ `LC_DYLD_CHAINED_FIXUPS` 的完整 bind/opcode 解释（目前只做 rebase 规模校验）
- ⬜ `objc_msgSend` 的完整汇编分发与 SUD 的 SIGSYS 信号处理器接线
- ⬜ Foundation / UIKit 全量控件、Metal 全量管线、XPC/Mach IPC 桥
- ⬜ 真机上的 LMK 进程优先级拦截与冷/热路径性能调优

### 路线图

| 里程碑 | 目标 |
| --- | --- |
| M1 ✅ | 可编译可测试骨架 + 注入工具 + 三语文档 + 全中文 CI |
| M1.5 ✅ | **执行闭环**：JIT 预补丁 + 原生执行 + 真 syscall 转发 + HLE 真实现（0.2.0） |
| M2 | dyld 符号绑定（让 guest 能调到 HLE）、chained fixups 完整 rebase/bind、objc_msgSend 分发、SUD 信号接线 |
| M3 | Foundation / UIKit 最小集 → **渲染出第一帧 UI**；Metal→Vulkan 前端打通 |
| M4 | 真机（root / pKVM 可用设备）性能调优、LMK 拦截 |

---

## 九、许可证与声明

本项目采用 **GPL-3.0-only**（GNU General Public License v3.0 only，不含 "or later"），全文见 [LICENSE](LICENSE)。任何衍生作品必须以相同许可证开源。

本项目仅用于**对本人合法持有、已自行脱壳的 IPA 做技术研究**。请自行遵守所在地区法律与应用许可协议；作者不对使用方式负责。项目不包含、也不分发任何 Apple 私有框架、系统库或受版权保护的二进制。

---

> 军师按：内核不用扒，PAC 不用管，AMFI 不用绕。硬件同源这一条，就是整个方案最大的便宜。

---

## 十、Android APK（0.3.0 新增，真能装进手机）

之前 0.2.0 的 CMake 产出的是 **Linux ELF 可执行文件 + 静态库**，能编译、能用 qemu 验证闭环，但**装不进手机** —— 缺的是 `NDK → .so → aapt2 → apksigner` 这一整条 Android 打包链。0.3.0 把它补上了。

**一键打包**（需要 Android SDK 的 build-tools/platform、NDK r25+、JDK、cmake、zip）：

```bash
export ANDROID_HOME=/path/to/android-sdk
./android/build-apk.sh
# 产物：./A-OS-Compat-arm64-v8a-debug.apk
```

五步链路：① NDK 把同一套 C 源码 + aarch64 汇编跳板编成 `lib/arm64-v8a/libaos_compat.so`；② `aapt2` 用 `android/app/src/main/AndroidManifest.xml` 生成基础 APK；③ 把 `.so` 塞进 APK 的 `lib/`；④ `zipalign` 4 字节对齐；⑤ `apksigner` 用自签 debug keystore 做 **v1+v2+v3** 签名。

**应用形态**：纯 `NativeActivity`（`android:hasCode="false"`），APK 里没有 `classes.dex`，也不需要一行 Java —— 系统直接 `dlopen` 我们的 `.so` 并调 `ANativeActivity_onCreate`。少一层 JNI 就少一次 ABI 边界开销。只发布 `arm64-v8a`，因为 iOS 砸壳包是 arm64 机器码。

**装上之后**：

```bash
adb install -r A-OS-Compat-arm64-v8a-debug.apk
adb logcat -s A-OS:V A-OS-GUEST:V
```

启动会建 rootless 越狱环境、跑两套内置 arm64 样本（退出码 42 / 15）、把 `A-OS NATIVE OK` 打到 logcat（guest 的 stdout 在 Android 上默认不可见，所以 `aos_trap_dispatch` 把 `write(1/2, ...)` 旁路到 `A-OS-GUEST` tag），并在 `ANativeWindow` 上直接提交第一帧。

**换成自己的砸壳包**：把脱壳后的 Mach-O 命名为 `payload.decrypted` 放进 `android/app/src/main/assets/`，重新跑 `build-apk.sh`，App 会优先加载它。CI 的第三个 job 会自动产出并上传这个 APK（Actions → Artifacts）。

debug 签名是自签的，安装时系统可能提示「未知来源」，允许即可。边界照旧：**跑通的是 syscall 级闭环，还跑不了任意真实 App 的 UI**。
