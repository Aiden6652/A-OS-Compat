# A-OS Compatibility Layer

> Run **decrypted iOS IPAs** (FairPlay removed) natively inside a virtualized environment on **ARM64 Android phones**, with a built-in rootless jailbreak environment and dylib injection support.
>
> **One-line premise: execution is virtualization — the guest's arm64 machine code runs natively on the hardware. Only the translation boundary is JIT-accelerated. No instruction translation, no full iOS emulation, no QEMU.**

| | |
| --- | --- |
| Version | `0.1.0` (compilable, tested core skeleton) |
| License | **GPL-3.0-only** (GPLv3 only, no "or later") |
| Architectures | Host `aarch64` Android / guest plain `arm64` |
| Docs | [中文 (default)](README.md) · English · [한국어](README.ko.md) |

---

## 1. The opening decision: fork UniXNU's XNU kernel, or write a userspace syscall compatibility layer?

**Verdict: go userspace. Do not fork the kernel.**

| Dimension | Forking UniXNU / patching XNU | **Userspace Darwin compatibility layer (this project)** |
| --- | --- | --- |
| Kernel | Must replace Android's Linux kernel or run XNU under KVM | Reuses the existing Linux kernel |
| Drivers | Requires rewriting Apple's board-support drivers (mostly proprietary, no source) | Only needs Linux `mmap` / `mprotect` / `prctl` / signals |
| Virtualization | `/dev/kvm` is usually locked down on consumer phones; pKVM risks **nested virtualization**, a performance black hole | No KVM at all — isolation via **Syscall User Dispatch** on a guest code address range |
| Page tables | XNU's 16KiB pages demand page-table surgery | iOS 16KiB is an integer multiple of Android's 4KiB, so `mprotect` alignment is free |
| Debuggability | A kernel panic blinds you | Entirely userspace: gdb and unit tests just work |

> UniXNU's value is "make XNU boot on a different board". Our board already has Linux; what is actually missing is the **Darwin ABI boundary**. Patch the boundary, not the kernel.

---

## 2. Three hard rules

1. **No full iOS emulation.** We do not load `dyld_shared_cache` (copyrighted, and `arm64e`/PAC). We follow the **High-Level Emulation (HLE)** approach validated by touchHLE: implement only the framework APIs the app actually calls.
2. **No instruction translation.** An ARM64 Android phone executes the IPA's `arm64` machine code **natively on the hardware** — no translation, no interpretation, no QEMU.
3. **JIT accelerates only the translation boundary; execution itself is virtualization.** The JIT compiles XNU ABI boundaries (`svc #0x80`, Mach traps, ObjC message bridges, hot framework calls) into directly-jumpable host trampolines. Cold paths go through SUD interception; hot `svc #0x80` sites are patched in place into `b <stub>` so no signal is ever taken again.

**Why this is cheap:** the vast majority of iOS apps are plain `arm64`, not `arm64e` — **no PAC**, no `PACIASP`/`AUTIASP` in function prologues. Hooks and trampolines are therefore a plain 4-byte `b`/`br` overwrite. We never load the `arm64e` system libraries anyway.

---

## 3. Pipeline

```
  aos-inject ── Mach-O parse + inject LC_LOAD_DYLIB into header padding
       │
       ▼
  host loader / in-house dyld
    · reserve + MAP_FIXED by relative segment offsets, W^X (R-X / RW-)
    · self-signed trust cache (we ARE the signature authority; no AMFI bypass)
    · rootless jailbreak: /var/jb + TweakInject + pspawn
       │  br to guest entry (aarch64/entry.S)
       ▼
  guest: IPA's own arm64 code — native hardware execution, zero translation
       │  svc #0x80 / Mach trap inside guest address range
       ▼
  Syscall User Dispatch (intercept by code address range)
     ├── cold: SIGSYS → table lookup → forward / emulate
     └── hot:  JIT rewrites svc into b <trampoline> → direct host jump
       ▼
  XNU→Linux translation: x16→x8, svc #0x80→#0, errno convention,
  open→openat(AT_FDCWD), Mach IPC→XPC bridge
       ▼
  HLE stubs: Foundation / UIKit / CoreGraphics / ObjC Runtime /
  Metal (AIR→SPIR-V→Turnip/Adreno Vulkan)
```

---

## 4. Key components

| Component | Approach | File |
| --- | --- | --- |
| Mach-O parser | Pure C, self-contained structs, zero Apple SDK dependency; strict bounds checks; thin/fat (auto-picks plain arm64 slice), chained fixups, encryption flag | `src/macho.c` |
| dylib injection | Consumes only linker-reserved **header padding**; appends `LC_LOAD_DYLIB` / `LC_LOAD_WEAK_DYLIB`, bumps `ncmds`/`sizeofcmds`; **never moves a byte of __TEXT / __LINKEDIT**; rejects still-encrypted binaries | `src/inject.c` |
| JIT emitter | Emits aarch64 machine code at runtime: `movz/movk` 64-bit loads + `br`, XNU call stubs, original-function trampolines, `svc→b` hot patches, W^X executable pages via `mmap`+`mprotect`. **Every encoding was verified against `clang --target=aarch64-linux-gnu` disassembly** | `src/jit_arm64.c` |
| Syscall interception | `PR_SET_SYSCALL_USER_DISPATCH` (Linux 5.11+) intercepts only the **guest code range**; host bionic/libc calls pass through untouched; switching personality writes one userspace selector byte; falls back to seccomp SIGSYS | `src/syscall_dispatch.c` |
| ABI translation | XNU: number in `x16`, `svc #0x80`, carry + `x0=errno`. Linux: number in `x8`, `svc #0`, `x0=-errno`. BSD numbers are disjoint; Mach traps are negative and emulated in userspace | `src/syscall_table.c` |
| Built-in jailbreak | Since we are the loader, **there is no AMFI to bypass**. We reproduce only userspace-visible semantics: `/var/jb` rootless layout, `DYLD_INSERT_LIBRARIES` + TweakInject plist filters, pspawn inheritance, self-signed trust cache, consistent jailbreak-detection answers | `src/jailbreak.c` |
| Sandbox | `NSHomeDirectory()` / Documents / Library / Caches / tmp redirected to the Android app-private directory; `..` escapes rejected; `/var/jb` mapped to the jailbreak root | `src/loader.c` |
| Graphics | No Apple private libraries; Metal → AIR → SPIR-V → Turnip/Adreno Vulkan frontend, aiming for the first rendered UI frame | `src/loader.c` |
| Context switch | aarch64 assembly trampoline: save callee-saved regs → switch to guest stack → `br x0`. Plain arm64 has no PAC, so no `paciasp`/`autiasp` | `src/aarch64/entry.S` |

**Pitfall checklist:** no KVM / no nested virtualization (avoiding the performance black hole); Android LMK differs from iOS jetsam, so process-priority interception is deferred to M4; graphics uses a Metal→Vulkan translation frontend (DXVK-style) to get the first frame out.

---

## 5. Build and test

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
cd build && ctest --output-on-failure
```

On x86_64, `entry.S` is skipped (only the C portion is compiled); on aarch64 it is included automatically. Current CI: **5/5 tests pass, 186 assertions, zero compiler warnings**.

### aarch64 cross-build (same as CI)

```bash
sudo apt-get install -y gcc-aarch64-linux-gnu
cmake -S . -B build-a64 -DCMAKE_TOOLCHAIN_FILE=aarch64-toolchain.cmake
cmake --build build-a64 -j$(nproc)
file build-a64/aos-info     # ELF 64-bit LSB pie executable, ARM aarch64
```

Cross artifacts are built but not executed on the host.

---

## 6. Tools

```bash
# Inspect a decrypted Mach-O: arch, encryption status, fixups, free header padding, all LCs
./build/aos-info Payload/App.decrypted

# Inject a dylib (only header padding is touched; output length is unchanged)
./build/aos-inject Payload/App.decrypted App.injected \
    @executable_path/AOSTweak.dylib

# Weak variant (missing library is non-fatal)
./build/aos-inject Payload/App.decrypted App.injected \
    /var/jb/usr/lib/TweakInject/Foo.dylib --weak
```

The original `LC_CODE_SIGNATURE` is invalidated by injection — but **the host loader is its own dyld and uses a self-signed trust cache, so no re-signing is needed**. Unlike a real jailbreak, there is no CoreTrust injection or PPL bypass: we hold the signing authority, so there is no AMFI to fool.

If header padding is insufficient, the tool tells you to relink with `-headerpad_max_install_names`.

---

## 7. Honest capability boundary

**0.1.0 is a compilable, testable, injectable core skeleton. It cannot yet run a full app UI.**

Delivered: Mach-O parsing / fat extraction / dylib injection (encrypted-binary rejection, low-padding detection); ARM64 JIT emitter (encodings disassembled and verified) with W^X pages; XNU→Linux syscall table (40 entries, argument rewriting and Mach trap emulation); Syscall User Dispatch layer (real aarch64 path + CI stub); rootless jailbreak environment (layout / trust cache / tweak filters / pspawn / detection); sandbox mapping; HLE stub registry; loader mapping and chained-fixups validation; 186 unit assertions plus x86_64 and aarch64 CI.

Not yet implemented: full bind/opcode interpretation for `LC_DYLD_CHAINED_FIXUPS` (only rebase scale is validated); full `objc_msgSend` assembly dispatch and SIGSYS handler wiring; the full Foundation/UIKit control set, Metal pipeline, and XPC/Mach IPC bridge; on-device LMK priority interception and cold/hot-path tuning.

| Milestone | Goal |
| --- | --- |
| M1 ✅ | Compilable, testable skeleton + injection tool + trilingual docs + CI |
| M2 | Full chained-fixups rebase/bind, objc_msgSend dispatch, SUD signal wiring |
| M3 | Minimal HLE set → **render the first UI frame**; Metal→Vulkan frontend |
| M4 | On-device (root / pKVM-capable) tuning and LMK interception |

---

## 8. License and disclaimer

Licensed **GPL-3.0-only** (GNU GPL v3.0 only, without "or later"); see [LICENSE](LICENSE). Derivative works must be released under the same license.

This project is for **research on IPAs you legally own and have decrypted yourself**. Comply with your local laws and app license agreements. The project contains and distributes no Apple private frameworks, system libraries, or copyrighted binaries.
