# A-OS 호환성 계층

> **ARM64 안드로이드 폰**에서 FairPlay 암호화가 제거된 **iOS 탈옥 IPA(복호화 IPA)**를 가상화 환경에서 네이티브로 실행하고, rootless 탈옥 환경과 dylib 주입을 지원합니다.
>
> **핵심 전제: 실행 부분은 가상화입니다. 게스트의 arm64 기계어는 하드웨어에서 그대로 네이티브 실행되고, JIT 가속은 '번역이 필요한 경계'에만 적용됩니다. 명령어 번역도, iOS 전체 에뮬레이션도, QEMU도 없습니다.**

| 항목 | 값 |
| --- | --- |
| 버전 | `0.2.0` (**실행 루프 동작**: 로드 → JIT 사전 패치 → 네이티브 실행 → 트랩 변환 → 게스트 복귀) |
| 라이선스 | **GPL-3.0-only** (GPLv3 한정, "or later" 없음) |
| 아키텍처 | 호스트 `aarch64` 안드로이드 / 게스트 일반 `arm64` |
| 문서 | [中文 (기본)](README.md) · [English](README.en.md) · 한국어 |

---

## 1. 출발점 판정: UniXNU의 XNU 커널을 뜯어고칠까, 사용자 공간 syscall 호환 계층을 만들까?

**결론: 사용자 공간으로 갑니다. 커널은 건드리지 않습니다.**

| 관점 | UniXNU / XNU 커널 개조 | **사용자 공간 Darwin 호환 계층 (본 프로젝트)** |
| --- | --- | --- |
| 커널 | 안드로이드의 Linux 커널을 교체하거나 KVM 위에 XNU를 올려야 함 | 기존 Linux 커널을 그대로 재사용 |
| 드라이버 | Apple 보드 지원 드라이버 전체를 다시 작성해야 함 (대부분 비공개, 소스 없음) | Linux의 `mmap` / `mprotect` / `prctl` / 시그널만 사용 |
| 가상화 | 일반 단말에서는 `/dev/kvm`이 잠겨 있는 경우가 많고, pKVM은 **중첩 가상화**라는 성능 블랙홀을 유발 | KVM 불필요. **Syscall User Dispatch**로 게스트 코드 주소 구간만 격리 |
| 페이지 테이블 | XNU의 16KiB 페이지 때문에 페이지 테이블 수술이 필요 | iOS 16KiB는 안드로이드 4KiB의 정수배라 `mprotect` 정렬이 공짜로 맞음 |
| 디버깅 | 커널 패닉이 나면 전부 깜깜해짐 | 전부 사용자 공간이라 gdb와 단위 테스트를 그대로 사용 가능 |

> UniXNU의 가치는 "XNU를 다른 보드에서 부팅시키는 것"입니다. 우리 보드에는 이미 Linux가 있고, 실제로 없는 것은 **Darwin ABI 경계**뿐입니다. 커널이 아니라 경계만 메우면 됩니다.

---

## 2. 세 가지 철칙

1. **iOS 전체를 에뮬레이션하지 않습니다.** `dyld_shared_cache`를 로드하지 않습니다(저작권 보호 대상이며 `arm64e`/PAC 적용). touchHLE로 검증된 **HLE(High-Level Emulation)** 방식을 따릅니다. 즉 앱이 실제로 호출하는 프레임워크 API만 구현합니다.
2. **명령어 번역을 하지 않습니다.** ARM64 안드로이드 폰은 IPA 안의 `arm64` 기계어를 **하드웨어에서 그대로 네이티브 실행**합니다. 번역도, 인터프리팅도, QEMU도 없습니다.
3. **번역 부분만 JIT로 가속하고, 실행 부분은 가상화입니다.** JIT는 XNU ABI 경계(`svc #0x80`, Mach trap, ObjC 메시지 브리지, 고빈도 프레임워크 호출)만 런타임에 호스트가 바로 점프할 수 있는 trampoline으로 컴파일합니다. 콜드 패스는 SUD로 가로채고, 핫한 `svc #0x80`은 게스트 코드 페이지에서 제자리를 `b <stub>`로 바꿔 이후에는 시그널조차 타지 않습니다.

**이렇게 값싸게 가능한 이유**: iOS 앱 대부분은 `arm64e`가 아니라 일반 `arm64`이며 **PAC가 없습니다.** 함수 프롤로그에 `PACIASP`/`AUTIASP`가 없으므로 hook과 trampoline은 4바이트 `b`/`br` 덮어쓰기로 끝납니다. 어차피 `arm64e` 시스템 라이브러리는 로드하지도 않습니다.

### touchHLE에 대하여: 껍데기만 빌리고, 심장은 바꾸지 않는다

"32비트 iOS 앱을 돌리는 touchHLE를 고치면 되는 거 아닌가?" 공식 저장소에서 확인한 네 가지 벽:

| 사실 | touchHLE | 영향 |
| --- | --- | --- |
| 라이선스 | 소스는 **MPL-2.0** (바이너리만 GPLv3-or-later) | 통째로 가져오면 `GPL-3.0-only`가 오염됨 |
| CPU 계층 | **dynarmic** 명령어 수준 재컴파일 ("emulated CPU") | 우리가 제거해야 할 명령어 번역 그 자체 |
| 아키텍처 | 공식 **"Never: 64-bit iOS"**, armv7 / iPhone OS 2.x–4.0.x 전용 | arm64 Mach-O 미지원, CPU 백엔드 교체 = 재작성 |
| 언어 | Rust + SDL + OpenGL ES | 본 프로젝트는 순수 C |

따라서 **fork 하지 않고 MPL 코드를 단 한 줄도 복사하지 않습니다** (라이선스는 순수 GPL-3.0-only 유지). 빌리는 것은 "시스템 프레임워크를 직접 구현한다"는 **HLE 껍데기**뿐입니다. 이 사용자 공간 의미는 CPU 비트폭과 무관하므로, 0.2.0에서 빈 스텁을 실제 동작하는 C 구현으로 바꿨습니다 (`NSLog` 실제 출력, `NSHomeDirectory` 샌드박스 경로 반환, `CGRectMake` 구조체 생성, `malloc/free` 실제 전달, ObjC/Metal 의사 핸들). 모두 `aos_hle_invoke()`로 분기합니다.

> 실용 정보: 예전 32비트 iOS 게임만 하고 싶다면 **touchHLE의 AArch64 Android APK를 그대로 설치**하면 됩니다. 다만 이는 armv7을 dynarmic으로 번역해 실행하는 방식이며, 우리의 64비트 네이티브 가상화와는 다른 이야기입니다.

---

## 3. 실행 흐름

```
  aos-inject ── Mach-O 파싱 + header padding에 LC_LOAD_DYLIB 주입
       │
       ▼
  호스트 로더 / 자체 dyld
    · segment 상대 오프셋으로 reserve + MAP_FIXED, W^X (R-X / RW-)
    · 자체 서명 trust cache (우리가 서명 판정 주체 → AMFI 우회 불필요)
    · rootless 탈옥 환경: /var/jb + TweakInject + pspawn
       │  게스트 엔트리로 br (aarch64/entry.S)
       ▼
  게스트: IPA 자체 arm64 기계어 — 하드웨어 네이티브 실행, 번역 0
       │  게스트 주소 구간 안의 svc #0x80 / Mach trap
       ▼
  Syscall User Dispatch (코드 주소 구간으로 가로챔)
     ├── 콜드: SIGSYS → 테이블 조회 → 전달 / 에뮬레이션
     └── 핫:   JIT가 svc를 b <trampoline>로 치환 → 호스트로 직접 점프
       ▼
  XNU→Linux 변환: x16→x8, svc #0x80→#0, errno 규약,
  open→openat(AT_FDCWD), Mach IPC→XPC 브리지
       ▼
  HLE 스텁: Foundation / UIKit / CoreGraphics / ObjC Runtime /
  Metal (AIR→SPIR-V→Turnip/Adreno Vulkan)
```

### 실행 루프가 실제로 동작한다 (0.2.0, 검증 완료)

`aos-run --selftest`는 실제 **arm64 기계어**를 끝까지 실행합니다:

```bash
cmake -S . -B build-a64 -DCMAKE_TOOLCHAIN_FILE=aarch64-toolchain.cmake
cmake --build build-a64 -j$(nproc)
qemu-aarch64-static -L /usr/aarch64-linux-gnu ./build-a64/aos-run --selftest
```

```
──── 게스트 실행 시작（하드웨어 네이티브 arm64 명령）────
A-OS NATIVE OK
  guest 종료 코드 : 42       ← 샘플 1: write 전달 + 종료 코드 반환
A-OS NATIVE OK
  guest 종료 코드 : 15       ← 샘플 2: write 반환값이 게스트 x0에 기록됨
```

동작 방식: `aos_exec_map()`이 게스트 이미지와 JIT 스텁 영역을 **인접하게** mmap 합니다 (`b`의 ±128MB 범위 보장). `aos_exec_patch_all()`이 각 트랩 지점마다 **전용 trampoline**(`mov64 x9, 복귀 주소` + `b <공유 스텁>`)을 만들고 `svc #0x80`을 `b <trampoline>`으로 덮어씁니다. `bl`이 아니라 `b`를 쓰므로 **`x30`은 절대 건드리지 않습니다**. `trampoline.S`가 현장을 저장하고 `aos_trap_dispatch()`를 호출해 **실제 Linux `syscall()`을 발행**한 뒤, `-errno`를 XNU의 `x0=errno + carry`로 되돌리고 현장을 복원해 `br x9`로 게스트에 복귀합니다. XNU `exit`는 호스트 프로세스를 죽이지 않고 `aos_exec_run()`으로 `longjmp`합니다. **패치된 트랩 명령 외에는 게스트 기계어가 단 1바이트도 바뀌지 않습니다.**

> **qemu에 대하여**: `qemu-aarch64`는 CI / 로컬 **논리 검증에만** 쓰이며 제품 실행 경로에는 절대 들어가지 않습니다. 실제 ARM64 기기에서는 게스트 arm64 명령이 하드웨어에서 네이티브 실행됩니다(qemu도, 명령어 번역도 없음). KVM / 중첩 가상화 / SUD / seccomp도 필요 없습니다. 트랩 지점은 최초 실행 전부터 이미 JIT 스텁이므로 항상 핫 패스입니다. `src/syscall_dispatch.c`는 게스트가 런타임에 코드를 생성하는 경우의 선택적 폴백으로 남겨 둡니다.

---

## 4. 주요 구성 요소

| 구성 요소 | 방식 | 파일 |
| --- | --- | --- |
| Mach-O 파서 | 순수 C, 자체 구조체 정의, Apple SDK 의존성 0. 엄격한 경계 검사. thin/fat(일반 arm64 slice 자동 선택), chained fixups, 암호화 플래그 지원 | `src/macho.c` |
| dylib 주입 | 링커가 남겨둔 **header padding**만 사용. `LC_LOAD_DYLIB` / `LC_LOAD_WEAK_DYLIB` 추가 후 `ncmds`/`sizeofcmds` 갱신. **__TEXT / __LINKEDIT는 1바이트도 옮기지 않음.** 암호화가 남은 바이너리는 거부 | `src/inject.c` |
| JIT 이미터 | 런타임에 aarch64 기계어 생성: `movz/movk` 64비트 즉치수 로드 + `br`, XNU 호출 스텁, 원본 함수 trampoline, `svc→b` 핫 패치, `mmap`+`mprotect` 기반 W^X 실행 페이지. **모든 인코딩은 `clang --target=aarch64-linux-gnu` 역어셈블로 검증** | `src/jit_arm64.c` |
| Syscall 가로채기 | `PR_SET_SYSCALL_USER_DISPATCH` (Linux 5.11+)로 **게스트 코드 구간**만 차단. 호스트 bionic/libc 호출은 무손실 통과. 페르소나 전환은 사용자 공간 selector 1바이트만 기록. 미지원 시 seccomp SIGSYS로 폴백 | `src/syscall_dispatch.c` |
| ABI 변환 | XNU: 번호는 `x16`, `svc #0x80`, carry + `x0=errno`. Linux: 번호는 `x8`, `svc #0`, `x0=-errno`. BSD 번호 체계는 별개이며 Mach trap은 음수이므로 사용자 공간에서 에뮬레이션 | `src/syscall_table.c` |
| 내장 탈옥 환경 | 우리가 로더이므로 **우회할 AMFI 자체가 없습니다.** 사용자 공간에 보이는 의미만 재현: `/var/jb` rootless 레이아웃, `DYLD_INSERT_LIBRARIES` + TweakInject plist Filter, pspawn 상속, 자체 서명 trust cache, 일관된 탈옥 탐지 응답 | `src/jailbreak.c` |
| 샌드박스 | `NSHomeDirectory()` / Documents / Library / Caches / tmp를 안드로이드 앱 전용 디렉터리로 리다이렉트. `..` 이스케이프 거부. `/var/jb`는 탈옥 루트로 매핑 | `src/loader.c` |
| 그래픽 | Apple 비공개 라이브러리 미사용. Metal → AIR → SPIR-V → Turnip/Adreno Vulkan 프런트엔드로 첫 UI 프레임을 목표 | `src/loader.c` |
| 컨텍스트 전환 | aarch64 어셈블리 trampoline: callee-saved 저장 → 게스트 스택 전환 → `br x0`. 일반 arm64에는 PAC가 없어 `paciasp`/`autiasp`를 내보내지 않음 | `src/aarch64/entry.S` |
| 실행 엔진 (0.2.0) | `svc #0x80` 스캔 → 지점별 JIT trampoline → `b`로 제자리 패치 → 호스트 어셈블리 트랩 핸들러가 실제 Linux syscall 전달 → `br`로 게스트 복귀. XNU `exit`는 longjmp | `src/exec.c` · `src/aarch64/trampoline.S` |
| 실제 HLE (0.2.0) | `aos_hle_invoke()`가 `NSLog` 출력, 샌드박스 홈, `CGRectMake`, `malloc/free`, ObjC/Metal 의사 핸들을 실제 처리 | `src/loader.c` |

**함정 회피**: KVM/중첩 가상화를 쓰지 않아 성능 블랙홀을 피합니다. 안드로이드 LMK는 iOS jetsam과 의미가 달라 프로세스 우선순위 가로채기는 M4로 미뤘습니다. 그래픽은 Metal→Vulkan 변환 프런트엔드(DXVK 계열 접근)로 첫 프레임을 먼저 확보합니다.

---

## 5. 빌드 및 테스트

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
cd build && ctest --output-on-failure
```

x86_64에서는 `entry.S` / `trampoline.S` 어셈블리를 건너뛰고(C 부분만 컴파일), aarch64에서는 자동으로 포함합니다. 현재 CI 결과: **테스트 6개 전부 통과, 어서션 250개, 컴파일 경고 0개**.

크로스 빌드 CI 작업은 `qemu-user-static`도 설치해
`qemu-aarch64-static -L /usr/aarch64-linux-gnu ./build-a64/aos-run --selftest`를 실행하고,
`A-OS NATIVE OK`, 종료 코드 `42`/`15`, HLE 검사, 최종 통과 문구를 확인합니다.
실제 ARM64 기기에서는 `./aos-run --selftest`만 실행하면 되며 qemu는 필요 없습니다.

### aarch64 크로스 빌드 (CI와 동일)

```bash
sudo apt-get install -y gcc-aarch64-linux-gnu
cmake -S . -B build-a64 -DCMAKE_TOOLCHAIN_FILE=aarch64-toolchain.cmake
cmake --build build-a64 -j$(nproc)
file build-a64/aos-info     # ELF 64-bit LSB pie executable, ARM aarch64
```

크로스 산출물은 빌드만 하고 호스트에서 실행하지는 않습니다.

---

## 6. 도구 사용법

```bash
# 복호화 Mach-O 검사: 아키텍처 / 암호화 여부 / fixups / header 여유 공간 / 전체 LC
./build/aos-info Payload/App.decrypted

# dylib 주입 (header padding만 변경, 출력 길이는 동일)
./build/aos-inject Payload/App.decrypted App.injected \
    @executable_path/AOSTweak.dylib

# 약한 의존성 버전 (라이브러리가 없어도 치명적이지 않음)
./build/aos-inject Payload/App.decrypted App.injected \
    /var/jb/usr/lib/TweakInject/Foo.dylib --weak
```

주입 후 기존 `LC_CODE_SIGNATURE`는 당연히 무효가 됩니다. 하지만 **호스트 로더가 곧 dyld이고 자체 서명 trust cache를 쓰므로 재서명이 필요 없습니다.** 실제 탈옥에서 필요한 CoreTrust 주입이나 PPL 우회와 달리, 서명 판정권이 우리에게 있으므로 속여야 할 AMFI가 존재하지 않습니다.

header padding이 부족하면 도구가 `-headerpad_max_install_names`로 재링크하라고 안내합니다.

### 이미지를 실제로 실행하기

```bash
./build/aos-run --selftest              # 내장 arm64 샘플 2개, 전체 루프 검증
./build/aos-run Payload/App.decrypted   # 복호화 Mach-O 로드 및 실행
./build/aos-run --emit /tmp/guest.macho # 크로스 아키텍처 검증용 샘플 내보내기
```

x86_64에서도 파싱·매핑·JIT 스텁 생성까지는 수행하며(바이트 검증에 유용), aarch64 기계어 실행은 **명시적으로 거부**합니다(종료 코드 2).

---

## 7. 솔직한 능력 범위

**0.2.0은 syscall 수준의 전체 루프를 실제로 실행하지만, 아직 임의의 실제 앱 UI를 구동하지는 못합니다.** 두 문장 모두 중요합니다. 검증 완료: `svc #0x80` 정적 사전 패치와 지점별 JIT trampoline, 실제 Linux `syscall()`을 발행하는 호스트 어셈블리 트랩 핸들러, 오류 규약 변환 및 결과를 게스트 `x0`에 기록한 뒤 `br` 복귀, 실제 arm64 샘플 2개가 `A-OS NATIVE OK`와 종료 코드 42/15를 출력, HLE 스텁의 실제 C 구현.

구현 완료: Mach-O 파싱 / fat 추출 / dylib 주입(암호화 바이너리 거부, padding 부족 감지), ARM64 JIT 이미터(인코딩 역어셈블 검증 완료)와 W^X 실행 페이지, XNU→Linux syscall 변환표(40개 항목, 인자 재작성 및 Mach trap 에뮬레이션 포함), Syscall User Dispatch 계층(실제 aarch64 경로 + CI용 스텁), rootless 탈옥 환경(디렉터리 트리 / trust cache / tweak Filter / pspawn / 탐지), 샌드박스 경로 매핑, HLE 스텁 등록, 로더 매핑 및 chained fixups 검증, 250개 단위 어서션과 x86_64 자체 테스트·aarch64 크로스 빌드·qemu 실행 루프 CI 검증.

미구현(이후 마일스톤): `LC_DYLD_CHAINED_FIXUPS`의 전체 bind/opcode 해석(현재는 rebase 규모 검증만), `objc_msgSend` 전체 어셈블리 디스패치와 SIGSYS 핸들러 배선, Foundation/UIKit 전체 컨트롤·Metal 전체 파이프라인·XPC/Mach IPC 브리지, 실기기 LMK 우선순위 가로채기 및 콜드/핫 경로 튜닝.

| 마일스톤 | 목표 |
| --- | --- |
| M1 ✅ | 컴파일·테스트 가능한 스켈레톤 + 주입 도구 + 3개 언어 문서 + CI |
| M1.5 ✅ | **실행 루프**: JIT 사전 패치 + 네이티브 실행 + 실제 syscall 전달 + 실제 HLE (0.2.0) |
| M2 | dyld 심볼 바인딩(게스트가 HLE를 호출하도록), chained fixups 전체 rebase/bind, objc_msgSend 디스패치, SUD 시그널 배선 |
| M3 | 최소 HLE 집합 → **첫 UI 프레임 렌더링**, Metal→Vulkan 프런트엔드 |
| M4 | 실기기(root / pKVM 가능 기기) 튜닝 및 LMK 가로채기 |

---

## 8. 라이선스 및 고지

본 프로젝트는 **GPL-3.0-only** (GNU GPL v3.0 한정, "or later" 없음)를 따릅니다. 전문은 [LICENSE](LICENSE)를 참고하십시오. 파생 저작물은 동일 라이선스로 공개해야 합니다.

본 프로젝트는 **본인이 적법하게 보유하고 직접 복호화한 IPA에 대한 기술 연구**만을 위한 것입니다. 거주 지역의 법령과 앱 라이선스 계약을 준수하십시오. 프로젝트는 Apple의 비공개 프레임워크, 시스템 라이브러리, 저작권 보호 바이너리를 포함하거나 배포하지 않습니다.
