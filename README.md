# Assembly Sysmon
**A bare-metal system monitoring and threat detection tool written entirely in x86_64 Assembly.**
No libc. No dependencies. Only the kernel.

[![License: CC0-1.0](https://img.shields.io/badge/License-CC0_1.0-lightgrey.svg)](https://creativecommons.org/publicdomain/zero/1.0/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20x86__64-blue.svg)](https://kernel.org)
[![Assembler](https://img.shields.io/badge/Assembler-NASM-red.svg)](https://nasm.us)
[![Made With](https://img.shields.io/badge/Made%20With-Assembly-orange.svg)](https://en.wikipedia.org/wiki/Assembly_language)

---

## Table of Contents

- [What Is This?](#what-is-this)
- [How It Looks](#how-it-looks)
- [Requirements](#requirements)
- [Step-by-Step Installation and Setup](#step-by-step-installation-and-setup)
- [Using the Build Script](#using-the-build-script-shortcut)
- [Understanding the Output](#understanding-the-output)
- [Threat Scoring — What the Numbers Mean](#threat-scoring--what-the-numbers-mean)
- [How It Works Under the Hood](#how-it-works-under-the-hood)
- [Known Issues and How They Were Fixed](#known-issues-and-how-they-were-fixed)
- [Extending the Tool](#extending-the-tool)
- [Frequently Asked Questions](#frequently-asked-questions)
- [License](#license)

---

## What Is This?

**ASM SysMon** is a real-time system monitor and basic threat detector written from scratch in **NASM x86_64 Assembly**. It has no C runtime, no shared libraries, and no external dependencies beyond the Linux kernel itself.

Every 3 seconds it:

1. Reads your CPU hardware information directly from the kernel virtual filesystem
2. Reads current memory usage and calculates utilisation as a percentage
3. Reads system load averages for the past 1, 5, and 15 minutes
4. Reads live network interface byte counters for every detected interface
5. Runs a lightweight threat scoring algorithm against those metrics
6. Displays everything colour-coded in your terminal and redraws the screen

The result is a fully functional monitoring tool that compiles to a binary under 50 kB and uses less than 100 kB of RAM at runtime.

---

## How It Looks

```
+=========================================================+
|                 System & Threat Monitor                |
|    Platform: Linux x86_64   |   Built in Assembly      |
+=========================================================+

[ CPU  ] Processor Information
- - - - - - - - - - - - - - - - - - - - - - - - - -
Model   : Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz
Cores   : 8
Speed   : 3800 MHz

[ MEM  ] Memory Status
- - - - - - - - - - - - - - - - - - - - - - - - - -
Total   : 32768000 kB
Free    : 18432000 kB
Used    : 14336000 kB
Usage   : 43%

[ LOAD ] System Load Average
- - - - - - - - - - - - - - - - - - - - - - - - - -
Averages: 0.52 0.48 0.41 1/843 12047

[ NET  ] Network Interfaces
- - - - - - - - - - - - - - - - - - - - - - - - - -
  lo:    0  0  0  0  0   0    0    0    0  0  0  0  0   0  0  0
  eth0:  48291830 56782 0  0  0   0  0  0  4291023 43291 0  0  0  0  0  0

[ THREAT ] Security Analysis
- - - - - - - - - - - - - - - - - - - - - - - - - -
  [+] Memory pressure is normal (<80%)
  [+] CPU load average is normal (<3.0)

Threat Score : [0] CLEAN  - No threats detected

[i] Auto-refreshing every 3 seconds  |  Ctrl+C to quit
```

---

## Requirements

| Requirement | Minimum Version | Purpose |
|---|---|---|
| **Linux kernel** | 4.x or newer (any distro) | The only OS supported |
| **x86_64 CPU** | Any 64-bit Intel or AMD | The binary uses 64-bit instructions only |
| **NASM** | 2.13+ | Assembles the `.asm` source into an object file |
| **GNU binutils (`ld`)** | Any recent version | Links the object file into an executable |
| **ANSI terminal** | Any modern terminal emulator | Required for colour output |

> You do **not** need GCC, Python, make, cmake, or any language runtime. NASM and `ld` are the only build tools required.

---

## Step-by-Step Installation and Setup

### Step 1: Install NASM

NASM (the Netwide Assembler) reads your `.asm` source and converts it into machine code in an object file (`.o`).

**Debian / Ubuntu / Linux Mint:**
```bash
sudo apt update
sudo apt install nasm
```

**Fedora / RHEL / CentOS / AlmaLinux:**
```bash
sudo dnf install nasm
```

**Arch Linux / Manjaro:**
```bash
sudo pacman -S nasm
```

**openSUSE:**
```bash
sudo zypper install nasm
```

Verify:
```bash
nasm --version
# Expected: NASM version 2.15.xx compiled on ...
```

If you see `command not found`, the install did not complete. Re-run and check for errors.

---

### Step 2: Install binutils (ld)

`ld` is the GNU linker. It turns the NASM object file into the final executable. On most distributions it is already installed as part of `binutils`, but if it is missing:

**Debian / Ubuntu:**
```bash
sudo apt install binutils
```

**Fedora / RHEL:**
```bash
sudo dnf install binutils
```

Verify:
```bash
ld --version
# Expected: GNU ld (GNU Binutils) 2.xx.x
```

---

### Step 3: Clone the Repository

```bash
git clone https://github.com/D3F4ULT-D3V/Assembly-Sysmon.git
cd Assembly-Sysmon
```

You should see:
```
Assembly-Sysmon/
├── sysmon.asm     <- the entire program source
├── build.sh       <- convenience build script
└── README.md      <- this file
```

---

### Step 4: Assemble the Source

```bash
nasm -f elf64 sysmon.asm -o sysmon.o
```

| Part | Meaning |
|---|---|
| `nasm` | The assembler program |
| `-f elf64` | Output format: 64-bit ELF (Linux native) |
| `sysmon.asm` | The input source file |
| `-o sysmon.o` | The output object file to create |

No output and a return to the prompt means success. Error messages like `error: symbol undefined` or `error: parser: instruction expected` indicate a corrupted download. Re-clone and try again.

---

### Step 5: Link the Object File

```bash
ld -o sysmon sysmon.o
```

| Part | Meaning |
|---|---|
| `ld` | The GNU linker |
| `-o sysmon` | Name of the executable to produce |
| `sysmon.o` | The object file from Step 4 |

Verify the result:
```bash
ls -lh sysmon
# Example: -rwxr-xr-x 1 user user 42K Jan 1 00:00 sysmon
```

The object file can be deleted:
```bash
rm sysmon.o
```

---

### Step 6: Run the Monitor

```bash
./sysmon
```

The terminal clears and the monitoring display appears. It refreshes every 3 seconds automatically.

If you get `Permission denied`:
```bash
chmod +x sysmon
./sysmon
```

---

### Step 7: Exit

Press **Ctrl + C** to terminate. The kernel sends `SIGINT` which ends the process immediately.

---

## Using the Build Script (Shortcut)

The included `build.sh` runs Steps 4 and 5 and checks for NASM first:

```bash
chmod +x build.sh
./build.sh
```

Expected output:
```
[*] Checking for NASM...
[*] Assembling sysmon.asm -> sysmon.o ...
[*] Linking sysmon.o -> sysmon ...
[+] Build successful!

Run with:  ./sysmon
Exit with: Ctrl+C
```

---

## Understanding the Output

The display has five sections. Here is what each one means and where the data comes from.

---

### CPU Section

```
[ CPU  ] Processor Information
- - - - - - - - - - - - - - - - - - - - - - - - - -
Model   : Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz
Cores   : 8
Speed   : 3800 MHz
```

**Source:** `/proc/cpuinfo`

The program opens this file, reads it into a buffer, and searches for three specific text labels using a byte-by-byte substring search. Everything after the `:` on the matched line is extracted and printed.

| Field | Label searched in `/proc/cpuinfo` | What it means |
|---|---|---|
| `Model` | `model name` | The full marketing name of your CPU as reported by the processor via CPUID |
| `Cores` | `cpu cores` | Physical core count, not including hyperthreaded logical cores |
| `Speed` | `cpu MHz` | Current operating clock speed in megahertz at the moment of the read |

> **Why does Speed show lower than the advertised spec?**
> `/proc/cpuinfo` shows the *current* operating frequency, not the maximum boost frequency. CPU frequency scaling (Intel SpeedStep, AMD P-states, the kernel's `cpufreq` governor) reduces clock speed automatically when the CPU is idle to save power. Under load you will see this number climb toward or past the base clock.

---

### MEM Section

```
[ MEM  ] Memory Status
- - - - - - - - - - - - - - - - - - - - - - - - - -
Total   : 32768000 kB
Free    : 18432000 kB
Used    : 14336000 kB
Usage   : 43%
```

**Source:** `/proc/meminfo`

All values are in **kilobytes (kB)**. To convert: divide by 1,024 for MB, by 1,048,576 for GB.

| Field | `/proc/meminfo` label | Formula | What it means |
|---|---|---|---|
| `Total` | `MemTotal:` | Direct read | Total physical RAM installed |
| `Free` | `MemFree:` | Direct read | RAM that is completely unallocated right now |
| `Used` |   | `Total - Free` | RAM currently used by the OS and all processes |
| `Usage` |   | `(Used / Total) x 100` | Utilisation as a whole-number percentage |

**Free vs Available:**
Linux aggressively uses spare RAM as a disk cache. Because of this, `MemFree` can look very low on a perfectly healthy system. The kernel reclaims that cache instantly when a process needs the memory. Low `MemFree` alone is not a problem. The field `MemAvailable:` (Linux 3.14+) gives a more realistic picture of what is actually available to new processes (this is a field planned for a future version).

**Threat relevance:** If `Usage` exceeds 80%, the threat score gets +1. Sustained high memory usage can indicate a runaway process, a memory leak, or deliberate resource exhaustion.

---

### LOAD Section

```
[ LOAD ] System Load Average
- - - - - - - - - - - - - - - - - - - - - - - - - -
Averages: 0.52 0.48 0.41 1/843 12047
```

**Source:** `/proc/loadavg`

The raw one-line contents of `/proc/loadavg` are printed after the `Averages:` label. The kernel writes exactly five space-separated values:

| Position | Example | What it means |
|---|---|---|
| 1st number | `0.52` | 1-minute load average |
| 2nd number | `0.48` | 5-minute load average |
| 3rd number | `0.41` | 15-minute load average |
| 4th value | `1/843` | Currently running threads / Total threads system-wide |
| 5th number | `12047` | PID of the most recently created process |

**What is a load average?**
The load average is the mean number of processes that were either running on a CPU or waiting in the run queue during that time window. A value of `1.0` on a single-core CPU means 100% utilisation. The same `1.0` on a 4-core CPU means 25% utilisation.

A rough guide for typical 2–8 core desktop and server systems:

| 1-min load | Interpretation |
|---|---|
| 0.0 – 1.0 | Idle to lightly loaded (healthy) |
| 1.0 – 3.0 | Moderate usage (normal) |
| 3.0 – 8.0 | Busy (investigate if sustained) |
| 8.0+ | Heavily loaded (likely a runaway process or attack) |

**Threat relevance:** The tool parses the integer part of the 1-minute average. If it reaches 3, the threat score gets +1. If it reaches 8, the threat score gets +2 instead. The load check can contribute at most +2 to the total score.

---

### NET Section

```
[ NET  ] Network Interfaces
- - - - - - - - - - - - - - - - - - - - - - - - - -
  lo:    0  0  0  0  0   0  0  0    0  0  0  0  0   0  0  0
  eth0:  48291830 56782 0  0  0   0  0  0  4291023 43291 0  0  0  0  0  0
```

**Source:** `/proc/net/dev`

The first two lines of `/proc/net/dev` are column headers. The program skips them and prints everything from the third line onward. Each line is one network interface.

The 17 columns left-to-right are:

| # | Label | Meaning |
|---|---|---|
| 1 | Interface | Interface name |
| 2 | RX bytes | Total bytes received since the interface came up |
| 3 | RX packets | Total packets received |
| 4 | RX errors | Receive-side hardware errors |
| 5 | RX drop | Packets dropped on receive (buffer full, etc.) |
| 6 | RX FIFO | FIFO buffer errors on receive |
| 7 | RX frame | Frame alignment errors |
| 8 | RX compressed | Compressed packets received |
| 9 | RX multicast | Multicast frames received |
| 10 | TX bytes | Total bytes transmitted |
| 11 | TX packets | Total packets transmitted |
| 12 | TX errors | Transmit-side hardware errors |
| 13 | TX drop | Packets dropped on transmit |
| 14 | TX FIFO | FIFO buffer errors on transmit |
| 15 | TX colls | Network collisions |
| 16 | TX carrier | Carrier signal losses |
| 17 | TX compressed | Compressed packets transmitted |

**Common interface names:**

| Name pattern | What it is |
|---|---|
| `lo` | Loopback — internal 127.0.0.1 traffic. Should show mostly zeros |
| `eth0`, `eth1` | Traditional Ethernet adapter names |
| `ens3`, `enp2s0`, `enp0s3` | Predictable network names used on modern systems |
| `wlan0`, `wlp3s0` | Wireless (Wi-Fi) adapter |
| `docker0`, `br-xxxxxxxx` | Docker virtual bridge interfaces |
| `virbr0` | Virtual bridge from libvirt/KVM |
| `tun0`, `tap0` | VPN tunnel interfaces |

> All byte counters are cumulative totals since the interface was last brought up (usually since boot). The NET section shows totals, not rates. To calculate bandwidth manually, compare RX/TX bytes across two refresh cycles and divide the difference by 3 seconds.

---

### THREAT Section

```
[ THREAT ] Security Analysis
- - - - - - - - - - - - - - - - - - - - - - - - - -
  [+] Memory pressure is normal (<80%)
  [+] CPU load average is normal (<3.0)

Threat Score : [0] CLEAN  - No threats detected
```

This section shows the result of every automated check and the final accumulated threat score. Each check line tells you whether that metric passed or triggered. The `Threat Score` line at the bottom is the overall verdict.

---

## Threat Scoring — What the Numbers Mean

Every refresh cycle starts at a threat score of **0**. Each check may add points. After all checks complete, the final total maps to a threat level.

### Individual Checks

**Memory Pressure Check**

| Condition | Score added | Display colour | Line shown |
|---|---|---|---|
| Usage < 80% | +0 | Green | `[+] Memory pressure is normal (<80%)` |
| Usage >= 80% | **+1** | Red | `[!] HIGH MEMORY PRESSURE DETECTED (>80%)` |

**CPU Load Check**

| Condition | Score added | Display colour | Line shown |
|---|---|---|---|
| 1-min load integer < 3 | +0 | Green | `[+] CPU load average is normal (<3.0)` |
| 1-min load integer >= 3 and < 8 | **+1** | Yellow | `[!] ELEVATED CPU LOAD DETECTED (>3.0)` |
| 1-min load integer >= 8 | **+2** | Red | `[!] CRITICAL CPU LOAD DETECTED (>8.0)` |

Note: the load check contributes +1 OR +2, never both. Maximum load contribution is +2.

### Final Threat Level Table

| Score | Colour | Level | Meaning and Recommended Response |
|---|---|---|---|
| **0** | Green | `CLEAN` | All metrics are within normal parameters. No action required. |
| **1** | Yellow | `LOW` | One metric is slightly elevated. Keep watching. Check whether a known process — a backup job, software update, or scheduled task — is responsible. |
| **2** | Yellow | `MEDIUM` | Two metrics are elevated simultaneously, or CPU load is critically high on its own. Run `ps aux --sort=-%cpu` and `ps aux --sort=-%mem` to identify the responsible process. Look for anything unfamiliar. |
| **3+** | Red | `HIGH` | Multiple metrics are simultaneously elevated. This combination is unusual during normal operation. Possible causes: runaway process, memory leak, cryptomining malware, or denial-of-service traffic. Investigate immediately. |

### Reading the Score Display

```
Threat Score : [0] CLEAN  - No threats detected
Threat Score : [1] LOW    - Elevated metrics, keep monitoring
Threat Score : [2] MEDIUM - Investigate system activity
Threat Score : [3+] HIGH  - Immediate investigation required!
```

The number inside `[ ]` is the raw accumulated score. Any score of 3 or above displays as `[3+]` because the appropriate response at that point is the same regardless of the exact number.

---

## How It Works Under the Hood

### The /proc Filesystem

Linux exposes nearly all live kernel state through a virtual filesystem at `/proc`. The files in `/proc` are not real files on disk — the kernel generates their contents on demand, every single time a process reads them. They always reflect the exact current state of the system at the moment of the read.

This program reads four of these virtual files:

| File | What the kernel writes there |
|---|---|
| `/proc/cpuinfo` | A text dump of CPU hardware info, key-value pairs per line, repeated for each logical CPU core |
| `/proc/meminfo` | A text dump of memory statistics for the whole system |
| `/proc/loadavg` | A single line: three load averages, a process count, and the most recent PID |
| `/proc/net/dev` | A table of per-interface network statistics, two header lines then one row per interface |

Each file is read with a raw `read()` syscall into a fixed 8,192-byte buffer (`fbuf`). The program then uses its own string search and number parsing routines to extract the values it needs.

---

### Syscalls — Talking to the Kernel Without a Library

A syscall is a controlled gateway from user space into the kernel. Normally you would call a C library function like `fopen()` or `printf()`, which internally invokes the kernel. This program skips that layer entirely.

In x86_64 Linux, a syscall is issued by:
1. Loading the syscall number into `rax`
2. Loading arguments into `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` in that order
3. Executing the `syscall` instruction
4. Reading the return value from `rax` (negative = error code)

The six syscalls this program uses
| Number | Name | How this program uses it |
|---|---|---|
| `0` | `read` | Reads bytes from an open `/proc` file into `fbuf` |
| `1` | `write` | Sends bytes from a buffer to stdout (file descriptor 1) |
| `2` | `open` | Opens a `/proc` virtual file path, returns a file descriptor |
| `3` | `close` | Closes a file descriptor after reading is done |
| `35` | `nanosleep` | Pauses the process for 3 seconds without burning CPU |
| `60` | `exit` | Terminates the process cleanly |

**Example — how `rdfile` opens, reads, and closes `/proc/meminfo`:**

```nasm
; 1. Open the file (O_RDONLY = 0)
mov  rax, 2           ; syscall: open
mov  rdi, p_meminfo   ; arg 1: pointer to "/proc/meminfo\0"
xor  rsi, rsi         ; arg 2: flags = 0 (O_RDONLY)
xor  rdx, rdx         ; arg 3: mode = 0 (ignored for read-only)
syscall               ; rax = file descriptor (>= 0) or error (< 0)
mov  rbx, rax         ; save the fd in rbx

; 2. Read its contents into fbuf
mov  rax, 0           ; syscall: read
mov  rdi, rbx         ; arg 1: the file descriptor
mov  rsi, fbuf        ; arg 2: destination buffer
mov  rdx, 8191        ; arg 3: max bytes to read
syscall               ; rax = bytes actually read
mov  byte [fbuf+rax], 0   ; null-terminate the buffer

; 3. Close the file descriptor
mov  rax, 3           ; syscall: close
mov  rdi, rbx         ; arg 1: the file descriptor
syscall
```

---

### The Refresh Loop

The `_start` entry point is an infinite loop that never voluntarily exits (Ctrl+C sends SIGINT which the kernel uses to terminate the process):

```
_start / .main_loop
   |
   +--> Clear screen (ANSI ESC[2J ESC[H)
   +--> Print banner
   +--> Reset: v_threat = 0, v_load_lvl = 0, v_mempct = 0
   +--> call show_cpu    (reads /proc/cpuinfo, prints CPU info)
   +--> call show_mem    (reads /proc/meminfo, may increment v_threat)
   +--> call show_load   (reads /proc/loadavg, may increment v_threat)
   +--> call show_net    (reads /proc/net/dev, prints interface table)
   +--> call show_threat (reads v_threat, prints final level)
   +--> Print footer
   +--> nanosleep(3 seconds)
   +--> jmp .main_loop
```

`v_threat` is reset to zero at the top of every cycle. `show_mem` and `show_load` conditionally increment it based on their findings. `show_threat` reads the final accumulated value and renders the appropriate level.

---

### Memory Layout

The program uses three ELF sections:

**`.data` — Initialised read/write data**
All string literals, ANSI escape codes, `/proc` file paths, search label strings, display label strings, and the `sleep_ts` timespec structure. This section is loaded from the binary into RAM at startup.

**`.bss` — Uninitialised read/write data**
Automatically zeroed by the kernel at startup. Contains all working variables:

| Variable | Size | Purpose |
|---|---|---|
| `fbuf` | 8,192 bytes | Universal scratch buffer — every `/proc` file is read here, one at a time |
| `nbuf` | 32 bytes | Scratch space for `prnuint` to build decimal digit strings |
| `v_memtotal` | 8 bytes | Total RAM in kB from the last cycle |
| `v_memfree_kb` | 8 bytes | Free RAM in kB |
| `v_memused` | 8 bytes | Computed used RAM in kB |
| `v_mempct` | 8 bytes | Computed memory usage percentage (0–100) |
| `v_threat` | 8 bytes | Accumulates the threat score; reset to 0 at the top of each cycle |
| `v_load_lvl` | 1 byte | Encodes load severity: 0 = normal, 1 = elevated (>=3), 2 = critical (>=8) |

**`.text` — Executable code**
All subroutines and the main loop. Mapped by the kernel as read-execute, not writable.

---

### Subroutine Reference

Every subroutine pushes the registers it will modify onto the stack at entry, does its work, then pops them in reverse order before returning. Callers never need to save registers around a call.

| Subroutine | Input | Output | What it does |
|---|---|---|---|
| `prsz` | `rdi` = null-terminated string pointer | — | Measures length byte-by-byte, then calls the `write` syscall |
| `prn` | `rdi` = data pointer, `rcx` = byte count | — | Calls `write` for exactly `rcx` bytes |
| `rdfile` | `rdi` = file path | `rax` = bytes read, `fbuf` filled | Open, read into `fbuf`, null-terminate, close |
| `findstr` | `rdi` = haystack, `rsi` = needle | `rax` = pointer to first match or 0 | Byte-by-byte O(n*m) substring search |
| `parsuint` | `rsi` = pointer into string | `rax` = parsed integer, `rsi` advanced past digits | Accumulates: `value = value * 10 + (char - '0')` |
| `skpws` | `rsi` = current position | `rsi` past whitespace | Advances `rsi` over spaces and tabs |
| `skpln` | `rsi` = current position | `rsi` at start of next line | Advances `rsi` past the next newline |
| `prnuint` | `rdi` = unsigned 64-bit integer | — | Builds decimal string in `nbuf` right-to-left via repeated division by 10, then calls `prn` |
| `getmemval` | `rdi` = label string | `rax` = parsed kB value or 0 | Calls `findstr`, advances past `:`, calls `skpws`, calls `parsuint` |
| `show_cpu` | — | Prints CPU section | Reads `/proc/cpuinfo`, calls `findstr` 3 times, prints model/cores/MHz |
| `show_mem` | — | Prints MEM section, updates `v_threat` and `v_mempct` | Reads `/proc/meminfo`, calls `getmemval` twice, computes stats, checks threshold |
| `show_load` | — | Prints LOAD section, updates `v_threat` and `v_load_lvl` | Reads `/proc/loadavg`, prints first line, parses integer part of 1-min load |
| `show_net` | — | Prints NET section | Reads `/proc/net/dev`, skips 2 headers with `skpln`, prints rest |
| `show_threat` | — | Prints THREAT section | Reads `v_threat` and `v_load_lvl`, prints per-check lines and final level |

---

### Register Calling Convention

This program uses a simplified consistent internal convention:

| Register | Role |
|---|---|
| `rax` | Syscall number (input) / return value (output) / scratch |
| `rdi` | First argument — pointer or integer |
| `rsi` | Second argument / rolling parse cursor in text-walking helpers |
| `rcx` | Third argument / loop counter |
| `rdx` | Fourth argument / byte count |
| `rbx` | Preserved working register — holds file descriptors across syscalls |
| `r12`–`r15` | Callee-saved locals within `show_*` functions, holding parsed values across multiple calls |
| `rsp` | Stack pointer — managed by push/pop/call/ret |

---

## Known Issues and How They Were Fixed

### Issue 1: Stack Misalignment Causing Silent Crashes

**Symptom:** Random segfaults, sometimes on startup, sometimes after several cycles. Crash location varied between runs.

**Cause:** The x86_64 ABI requires `rsp` to be 16-byte aligned before a `syscall`. The `call` instruction pushes an 8-byte return address, breaking alignment. An odd number of additional register pushes inside a subroutine before a syscall compounds the misalignment. Some syscalls produce silent corruption when the stack is misaligned.

**Fix:** Every subroutine's push/pop sequences were audited to ensure an even total number of 8-byte pushes (including the implicit `call` push) at every point where a syscall fires. Where a function naturally pushed an odd number of registers, a spare `push`/`pop` pair was added to keep the total even and `rsp` 16-byte aligned.

---

### Issue 2: File Descriptor Leak in rdfile

**Symptom:** After extended runtime the program would produce empty sections. On some systems it eventually failed to open any new files.

**Cause:** In an early version, the file descriptor returned by `open` was held in `rax`. The subsequent `read` syscall overwrote `rax` with the byte count. The `close` call that followed received a garbage value instead of the original fd. The `/proc` file descriptor was never closed, leaking one per section per cycle. Linux limits each process to 1,024 open file descriptors by default. When that limit was hit, all `open` calls began returning errors.

**Fix:** The file descriptor is moved from `rax` into `rbx` immediately after `open` returns, before any other syscall runs. The kernel does not modify `rbx` during a syscall. `rbx` holds the fd safely across the `read` call and is available for `close`.

---

### Issue 3: findstr False-Matching on /proc/meminfo Labels

**Symptom:** The `MemFree:` value parsed as wildly incorrect on certain kernel versions.

**Cause:** The original search label was `MemFree` (no colon). Some kernels include a field called `MemFreeSwap:` or `MemFreeCma:`. The `findstr` routine found the substring `MemFree` inside `MemFreeSwap:`, then parsed the number after the colon in `MemFreeSwap:` — a completely different value.

**Fix:** All `/proc/meminfo` search labels were extended to include the colon: `MemTotal:`, `MemFree:`, `MemAvailable:`. Since `MemFreeSwap:` begins with a different string before the colon, `findstr` no longer false-matches.

---

### Issue 4: Integer-only Load Parsing vs Fractional Thresholds

**Symptom:** A sustained load of `2.99` did not trigger the elevated threshold despite being within rounding distance of 3.

**Cause:** `parsuint` stops at the `.` character because it is not a digit. The fractional component is discarded. A load of `2.99` is parsed as `2`, which is below the `>= 3` threshold.

**Fix:** The thresholds were set at whole integer boundaries intentionally. A genuine transition from 2.99 to 3.00 requires the integer part to actually increment. This prevents false positives from transient spikes that briefly push a decimal value close to a threshold without meaningfully crossing it. The trade-off is that a score right at `2.99` is not flagged — this is an acceptable and deliberate design decision.

---

### Issue 5: prnuint Printing Nothing for Zero

**Symptom:** When a metric parsed as zero — a fresh network interface with no traffic, or a failed parse returning 0 — `prnuint` printed an empty string rather than `0`.

**Cause:** The original digit loop began with `test rax, rax` / `jz .done`. For an input of zero, it jumped immediately to the print step with an empty buffer — the `nbuf` pointer pointed at a null terminator, so `prn` wrote zero bytes.

**Fix:** A special case was inserted before the loop: if `rax == 0`, write the ASCII character `'0'` directly into `nbuf` and skip the division loop. The print step then correctly outputs a single `0`.

---

### Issue 6: Terminal Flicker on Refresh

**Symptom:** On slow SSH sessions or sensitive displays, a brief blank screen was visible between each 3-second refresh cycle.

**Cause:** The `ESC[2J ESC[H` escape sequence erases the screen and moves the cursor to the top-left before any new content is written. On a slow connection, the time between that clear and the first content write is long enough to be visible as a flash.

**Fix:** No structural fix was implemented in this version. A proper solution would involve writing the complete new frame into a memory buffer first and sending it in a single `write` call, minimising the blank window — this is the approach `ncurses`-based tools use. For a monitor with a 3-second refresh interval the flicker is generally acceptable. This is a planned improvement for a future release.

---

## Extending the Tool

Every monitoring section follows the same three-step pattern:
1. Call `rdfile` with a `/proc` path
2. Use `findstr` + `parsuint` (or just print the raw buffer) to extract values
3. Optionally increment `[v_threat]` if a threshold is crossed

**Adding a new data source:**

```nasm
; In .data:
p_myfile      db '/proc/something',0
lbl_myfield   db 'MyLabel:',0
h_mysection   db 10,27,'[1;33m','[ NEW ] My Section',27,'[0m',10,0

; In .text:
show_mydata:
    push rdi
    push r12

    mov  rdi, h_mysection
    call prsz
    mov  rdi, s_sep
    call prsz

    mov  rdi, p_myfile
    call rdfile
    test rax, rax
    jz   .done

    mov  rdi, lbl_myfield
    call getmemval        ; rax = parsed value
    mov  r12, rax

    cmp  rax, 1000        ; your threshold
    jl   .print
    mov  rax, [v_threat]
    inc  rax
    mov  [v_threat], rax

.print:
    mov  rdi, r12
    call prnuint
    mov  rdi, s_newline
    call prsz

.done:
    pop  r12
    pop  rdi
    ret
```

Then add `call show_mydata` to `.main_loop` in `_start` before `call show_threat`.

**Changing the refresh interval:**

```nasm
sleep_ts:
    dq 5    ; tv_sec  — change this (seconds)
    dq 0    ; tv_nsec — nanoseconds (0 to 999,999,999)
```

**Changing threat thresholds:**

In `show_mem`:
```nasm
cmp  r15, 80    ; memory % threshold — change 80 to your value
```

In `show_load`:
```nasm
cmp  rax, 8     ; critical load threshold
cmp  rax, 3     ; elevated load threshold
```

On a 16-core server, adjust the critical threshold to be closer to 16 since a load of 8 only represents 50% utilisation there.
