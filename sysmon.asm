; =============================================================================
; sysmon.asm  -  Assembly System Monitor & Threat Detection Tool
; =============================================================================
; Platform : Linux x86_64
; Assembler: NASM
;
; BUILD:
;   nasm -f elf64 sysmon.asm -o sysmon.o
;   ld -o sysmon sysmon.o
;
; RUN:
;   ./sysmon
;   (Ctrl+C to exit)
;
; WHAT IT DOES:
;   - Reads /proc/cpuinfo   -> CPU model, core count, frequency
;   - Reads /proc/meminfo   -> Total/Free/Used RAM, usage %
;   - Reads /proc/loadavg   -> 1/5/15 minute load averages
;   - Reads /proc/net/dev   -> Network interface RX/TX stats
;   - Calculates a threat score based on:
;       Memory usage > 80%   -> +1
;       1-min load  > 3.0    -> +1
;       1-min load  > 8.0    -> +2 (replaces +1)
;   - Displays colour-coded threat level: CLEAN / LOW / MEDIUM / HIGH
;   - Auto-refreshes every 3 seconds
; =============================================================================

bits 64

; ── Linux x86_64 syscall numbers ──────────────────────────────────────────────
%define SYS_READ       0
%define SYS_WRITE      1
%define SYS_OPEN       2
%define SYS_CLOSE      3
%define SYS_NANOSLEEP  35
%define SYS_EXIT       60

%define STDOUT         1
%define BUFSZ          8192

; =============================================================================
section .data
; =============================================================================

; ── ANSI escape codes (null-terminated) ───────────────────────────────────────
ansi_reset   db 27,'[0m',0
ansi_red     db 27,'[1;31m',0
ansi_green   db 27,'[1;32m',0
ansi_yellow  db 27,'[1;33m',0
ansi_cyan    db 27,'[1;36m',0

s_clear      db 27,'[2J',27,'[H',0   ; clear screen + cursor home

; ── Banner ────────────────────────────────────────────────────────────────────
s_banner:
    db 27,'[1;36m'
    db '+=========================================================+',10
    db '|                 System & Threat Monitor                |',10
    db '|    Platform: Linux x86_64   |   Built in Assembly      |',10
    db '+=========================================================+',10
    db 27,'[0m',0

; ── Section headers ───────────────────────────────────────────────────────────
h_cpu    db 10,27,'[1;33m','[ CPU  ] Processor Information',27,'[0m',10,0
h_mem    db 10,27,'[1;33m','[ MEM  ] Memory Status',27,'[0m',10,0
h_load   db 10,27,'[1;33m','[ LOAD ] System Load Average',27,'[0m',10,0
h_net    db 10,27,'[1;33m','[ NET  ] Network Interfaces',27,'[0m',10,0
h_threat db 10,27,'[1;31m','[ THREAT ] Security Analysis',27,'[0m',10,0

s_sep    db '- - - - - - - - - - - - - - - - - - - - - - - - - -',10,0

; ── /proc file paths ──────────────────────────────────────────────────────────
p_cpuinfo  db '/proc/cpuinfo',0
p_meminfo  db '/proc/meminfo',0
p_loadavg  db '/proc/loadavg',0
p_netdev   db '/proc/net/dev',0

; ── Labels to search for in /proc/cpuinfo ─────────────────────────────────────
lbl_model  db 'model name',0
lbl_cores  db 'cpu cores',0
lbl_mhz    db 'cpu MHz',0

; ── Labels to search for in /proc/meminfo ─────────────────────────────────────
lbl_memtot db 'MemTotal:',0
lbl_memfre db 'MemFree:',0
lbl_memavl db 'MemAvailable:',0

; ── Display labels ────────────────────────────────────────────────────────────
s_cpu_model db 'Model   : ',0
s_cpu_cores db 'Cores   : ',0
s_cpu_mhz   db 'Speed   : ',0
s_mhz_sfx   db ' MHz',10,0

s_mem_tot   db 'Total   : ',0
s_mem_fre   db 'Free    : ',0
s_mem_use   db 'Used    : ',0
s_mem_pct   db 'Usage   : ',0
s_kb_nl     db ' kB',10,0
s_pct_nl    db '%',10,0
s_newline   db 10,0

s_load_lbl  db 'Averages: ',0

; ── Threat analysis strings ───────────────────────────────────────────────────
s_thr_label db 10,'Threat Score : ',0

s_thr_0:
    db 27,'[1;32m','[0] CLEAN  - No threats detected',27,'[0m',10,0
s_thr_1:
    db 27,'[1;33m','[1] LOW    - Elevated metrics, keep monitoring',27,'[0m',10,0
s_thr_2:
    db 27,'[1;33m','[2] MEDIUM - Investigate system activity',27,'[0m',10,0
s_thr_3p:
    db 27,'[1;31m','[3+] HIGH  - Immediate investigation required!',27,'[0m',10,0

; Per-check status lines
s_ok_mem:
    db '  ',27,'[0;32m','[+] Memory pressure is normal (<80%)',27,'[0m',10,0
s_warn_mem:
    db '  ',27,'[1;31m','[!] HIGH MEMORY PRESSURE DETECTED  (>80%)',27,'[0m',10,0
s_ok_load:
    db '  ',27,'[0;32m','[+] CPU load average is normal (<3.0)',27,'[0m',10,0
s_warn_load_med:
    db '  ',27,'[1;33m','[!] ELEVATED CPU LOAD DETECTED     (>3.0)',27,'[0m',10,0
s_warn_load_hi:
    db '  ',27,'[1;31m','[!] CRITICAL CPU LOAD DETECTED     (>8.0)',27,'[0m',10,0

s_net_hdr   db '  Interface         RX bytes        TX bytes',10,0
s_net_sep   db '  -----------       ----------      ----------',10,0

; ── Footer ────────────────────────────────────────────────────────────────────
s_footer:
    db 10,27,'[0;36m'
    db '[i] Auto-refreshing every 3 seconds  |  Ctrl+C to quit'
    db 27,'[0m',10,0

; ── Sleep interval: 3 seconds ─────────────────────────────────────────────────
sleep_ts:
    dq 3       ; tv_sec  = 3
    dq 0       ; tv_nsec = 0

; =============================================================================
section .bss
; =============================================================================

fbuf          resb BUFSZ     ; file I/O scratch buffer (8192 bytes)
nbuf          resb 32        ; number-to-string conversion scratch

; Stored metric values (written by show_* functions, read by show_threat)
v_memtotal    resq 1
v_memfree_kb  resq 1
v_memused     resq 1
v_mempct      resq 1         ; percentage 0-100
v_threat      resq 1         ; accumulated threat score
v_load_lvl    resb 1         ; 0=ok, 1=med (>3), 2=high (>8)

; =============================================================================
section .text
global _start
; =============================================================================

; ─────────────────────────────────────────────────────────────────────────────
; prsz  -  print a null-terminated string to stdout
;   IN : rdi = pointer to string
;   Preserves all registers.
; ─────────────────────────────────────────────────────────────────────────────
prsz:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi

    ; measure length
    mov  rcx, rdi
    xor  rdx, rdx
.prsz_len:
    cmp  byte [rcx + rdx], 0
    je   .prsz_write
    inc  rdx
    jmp  .prsz_len
.prsz_write:
    test rdx, rdx
    jz   .prsz_done
    mov  rsi, rdi
    mov  rdi, STDOUT
    mov  rax, SYS_WRITE
    syscall
.prsz_done:
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    ret

; ─────────────────────────────────────────────────────────────────────────────
; prn  -  print exactly N bytes to stdout
;   IN : rdi = pointer to data
;        rcx = byte count
;   Preserves all registers.
; ─────────────────────────────────────────────────────────────────────────────
prn:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi

    test rcx, rcx
    jz   .prn_done

    mov  rsi, rdi
    mov  rdx, rcx
    mov  rdi, STDOUT
    mov  rax, SYS_WRITE
    syscall
.prn_done:
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    ret

; ─────────────────────────────────────────────────────────────────────────────
; rdfile  -  open/read a file into fbuf, null-terminate it, then close
;   IN : rdi = path (null-terminated)
;   OUT: rax = bytes read  (0 on error)
;        fbuf contains file contents
; ─────────────────────────────────────────────────────────────────────────────
rdfile:
    push rbx
    push rdx
    push rsi
    push rdi

    ; open(path, O_RDONLY=0, 0)
    mov  rax, SYS_OPEN
    xor  rsi, rsi
    xor  rdx, rdx
    syscall
    test rax, rax
    js   .rdfile_err

    mov  rbx, rax          ; save fd

    ; read(fd, fbuf, BUFSZ-1)
    mov  rax, SYS_READ
    mov  rdi, rbx
    mov  rsi, fbuf
    mov  rdx, BUFSZ - 1
    syscall

    push rax
    cmp  rax, 0
    jl   .rdfile_close
    mov  rcx, rax
    mov  byte [fbuf + rcx], 0   ; null-terminate

.rdfile_close:
    push rax
    mov  rax, SYS_CLOSE
    mov  rdi, rbx
    syscall
    pop  rax
    pop  rax               ; restore bytes-read
    jmp  .rdfile_done

.rdfile_err:
    xor  rax, rax

.rdfile_done:
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rbx
    ret

; ─────────────────────────────────────────────────────────────────────────────
; findstr  -  locate needle inside haystack (byte search, case-sensitive)
;   IN : rdi = haystack ptr (null-terminated)
;        rsi = needle ptr   (null-terminated)
;   OUT: rax = ptr to first occurrence inside haystack, or 0 if not found
; ─────────────────────────────────────────────────────────────────────────────
findstr:
    push rbx
    push rcx
    push rdx
    push r8

    mov  rbx, rdi          ; rbx = current haystack scan pos

.fs_outer:
    cmp  byte [rbx], 0
    je   .fs_notfound

    mov  rcx, rbx          ; rcx = compare position in haystack
    mov  rdx, rsi          ; rdx = needle scan (reset each outer step)

.fs_inner:
    cmp  byte [rdx], 0     ; end of needle → match!
    je   .fs_found
    mov  r8b, [rcx]
    cmp  r8b, [rdx]
    jne  .fs_advance
    inc  rcx
    inc  rdx
    jmp  .fs_inner

.fs_advance:
    inc  rbx
    jmp  .fs_outer

.fs_found:
    mov  rax, rbx
    jmp  .fs_done

.fs_notfound:
    xor  rax, rax

.fs_done:
    pop  r8
    pop  rdx
    pop  rcx
    pop  rbx
    ret

; ─────────────────────────────────────────────────────────────────────────────
; parsuint  -  parse an unsigned decimal integer from a string
;   IN : rsi = pointer into string
;   OUT: rax = parsed value
;        rsi = updated (points to first non-digit byte)
;   Clobbers: rcx
; ─────────────────────────────────────────────────────────────────────────────
parsuint:
    xor  rax, rax
.pu_loop:
    movzx rcx, byte [rsi]
    sub  rcx, '0'
    js   .pu_done
    cmp  rcx, 9
    ja   .pu_done
    imul rax, rax, 10
    add  rax, rcx
    inc  rsi
    jmp  .pu_loop
.pu_done:
    ret

; ─────────────────────────────────────────────────────────────────────────────
; skpws  –  skip spaces/tabs at rsi, advance rsi past them
;   IN/OUT: rsi  (modified in place)
;   Clobbers: rax
; ─────────────────────────────────────────────────────────────────────────────
skpws:
.skpws_lp:
    movzx rax, byte [rsi]
    cmp  al, ' '
    je   .skpws_skip
    cmp  al, 9
    je   .skpws_skip
    ret
.skpws_skip:
    inc  rsi
    jmp  .skpws_lp

; ─────────────────────────────────────────────────────────────────────────────
; skpln  –  advance rsi to start of next line (past the '\n')
;   IN/OUT: rsi  (modified in place)
; ─────────────────────────────────────────────────────────────────────────────
skpln:
.skpln_lp:
    cmp  byte [rsi], 0
    je   .skpln_done
    cmp  byte [rsi], 10
    je   .skpln_nl
    inc  rsi
    jmp  .skpln_lp
.skpln_nl:
    inc  rsi
.skpln_done:
    ret

; ─────────────────────────────────────────────────────────────────────────────
; prnuint  –  print an unsigned 64-bit integer in decimal
;   IN : rdi = value
;   Preserves all registers.
; ─────────────────────────────────────────────────────────────────────────────
prnuint:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi

    ; Build digits right-to-left into nbuf[0..30], null at nbuf[31]
    mov  rax, rdi
    lea  rbx, [nbuf + 31]
    mov  byte [rbx], 0

    test rax, rax
    jnz  .pu2_convert
    dec  rbx
    mov  byte [rbx], '0'
    jmp  .pu2_print

.pu2_convert:
    test rax, rax
    jz   .pu2_print
    xor  rdx, rdx
    mov  rcx, 10
    div  rcx               ; rax = q, rdx = digit
    add  dl, '0'
    dec  rbx
    mov  [rbx], dl
    jmp  .pu2_convert

.pu2_print:
    lea  rsi, [nbuf + 31]
    sub  rsi, rbx          ; length
    mov  rcx, rsi
    mov  rdi, rbx
    call prn

    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    ret

; ─────────────────────────────────────────────────────────────────────────────
; getmemval  –  extract a kB value from /proc/meminfo by label
;   NOTE: fbuf must already contain /proc/meminfo content
;   IN : rdi = label (e.g.  "MemTotal:")
;   OUT: rax = value in kB, or 0 if not found
; ─────────────────────────────────────────────────────────────────────────────
getmemval:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi

    mov  rsi, rdi          ; needle = label
    mov  rdi, fbuf         ; haystack = file buffer
    call findstr
    test rax, rax
    jz   .gmv_notfound

    mov  rsi, rax          ; rsi → start of label in fbuf
.gmv_to_colon:
    cmp  byte [rsi], ':'
    je   .gmv_past_colon
    cmp  byte [rsi], 0
    je   .gmv_notfound
    inc  rsi
    jmp  .gmv_to_colon
.gmv_past_colon:
    inc  rsi               ; skip ':'
    call skpws             ; skip spaces (rsi advances)
    call parsuint          ; rax = numeric value, rsi updated
    jmp  .gmv_done

.gmv_notfound:
    xor  rax, rax

.gmv_done:
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    ret

; =============================================================================
; show_cpu  –  display CPU hardware information from /proc/cpuinfo
; =============================================================================
show_cpu:
    push r12
    push r13
    push rdi
    push rsi
    push rcx

    mov  rdi, h_cpu
    call prsz
    mov  rdi, s_sep
    call prsz

    mov  rdi, p_cpuinfo
    call rdfile
    test rax, rax
    jz   .sc_done

    ; ── CPU model name ───────────────────────────────────────────────────────
    mov  rdi, fbuf
    mov  rsi, lbl_model
    call findstr
    test rax, rax
    jz   .sc_cores

    mov  rsi, rax
.sc_col1:
    cmp  byte [rsi], ':'
    je   .sc_past_col1
    cmp  byte [rsi], 0
    je   .sc_cores
    inc  rsi
    jmp  .sc_col1
.sc_past_col1:
    inc  rsi
    call skpws             ; rsi → first char of model string

    ; count chars to end of line
    push rsi
    xor  rcx, rcx
.sc_cnt_model:
    mov  al,  [rsi + rcx]
    cmp  al,  10
    je   .sc_prn_model
    cmp  al,  0
    je   .sc_prn_model
    inc  rcx
    jmp  .sc_cnt_model
.sc_prn_model:
    mov  rdi, s_cpu_model
    call prsz
    pop  rdi               ; ptr to model text
    call prn               ; rcx bytes
    mov  rdi, s_newline
    call prsz

    ; ── Core count ───────────────────────────────────────────────────────────
.sc_cores:
    mov  rdi, fbuf
    mov  rsi, lbl_cores
    call findstr
    test rax, rax
    jz   .sc_mhz

    mov  rsi, rax
.sc_col2:
    cmp  byte [rsi], ':'
    je   .sc_past_col2
    cmp  byte [rsi], 0
    je   .sc_mhz
    inc  rsi
    jmp  .sc_col2
.sc_past_col2:
    inc  rsi
    call skpws
    call parsuint          ; rax = core count

    push rax
    mov  rdi, s_cpu_cores
    call prsz
    pop  rdi
    call prnuint
    mov  rdi, s_newline
    call prsz

    ; ── Clock speed (MHz) ────────────────────────────────────────────────────
.sc_mhz:
    mov  rdi, fbuf
    mov  rsi, lbl_mhz
    call findstr
    test rax, rax
    jz   .sc_done

    mov  rsi, rax
.sc_col3:
    cmp  byte [rsi], ':'
    je   .sc_past_col3
    cmp  byte [rsi], 0
    je   .sc_done
    inc  rsi
    jmp  .sc_col3
.sc_past_col3:
    inc  rsi
    call skpws

    ; print up to '.' or newline (integer part of MHz)
    push rsi
    xor  rcx, rcx
.sc_cnt_mhz:
    mov  al, [rsi + rcx]
    cmp  al, '.'
    je   .sc_prn_mhz
    cmp  al, 10
    je   .sc_prn_mhz
    cmp  al, 0
    je   .sc_prn_mhz
    inc  rcx
    jmp  .sc_cnt_mhz
.sc_prn_mhz:
    mov  rdi, s_cpu_mhz
    call prsz
    pop  rdi
    call prn
    mov  rdi, s_mhz_sfx
    call prsz

.sc_done:
    pop  rcx
    pop  rsi
    pop  rdi
    pop  r13
    pop  r12
    ret

; =============================================================================
; show_mem  –  display memory statistics and update threat score
; =============================================================================
show_mem:
    push r12
    push r13
    push r14
    push r15
    push rdi
    push rsi

    mov  rdi, h_mem
    call prsz
    mov  rdi, s_sep
    call prsz

    ; read /proc/meminfo
    mov  rdi, p_meminfo
    call rdfile
    test rax, rax
    jz   .sm_done

    ; ── Parse MemTotal ───────────────────────────────────────────────────────
    mov  rdi, lbl_memtot
    call getmemval
    mov  r12, rax
    mov  [v_memtotal], rax

    ; ── Parse MemFree ────────────────────────────────────────────────────────
    mov  rdi, lbl_memfre
    call getmemval
    mov  r13, rax
    mov  [v_memfree_kb], rax

    ; ── Calculate used & percentage ──────────────────────────────────────────
    mov  r14, r12
    sub  r14, r13          ; r14 = used kB
    mov  [v_memused], r14

    xor  r15, r15          ; r15 = percentage
    test r12, r12
    jz   .sm_print

    mov  rax, r14
    imul rax, 100
    xor  rdx, rdx
    div  r12
    mov  r15, rax
    mov  [v_mempct], rax

    ; ── Threat check ─────────────────────────────────────────────────────────
    cmp  r15, 80
    jl   .sm_print
    mov  rax, [v_threat]
    inc  rax
    mov  [v_threat], rax

    ; ── Print values ─────────────────────────────────────────────────────────
.sm_print:
    mov  rdi, s_mem_tot
    call prsz
    mov  rdi, r12
    call prnuint
    mov  rdi, s_kb_nl
    call prsz

    mov  rdi, s_mem_fre
    call prsz
    mov  rdi, r13
    call prnuint
    mov  rdi, s_kb_nl
    call prsz

    mov  rdi, s_mem_use
    call prsz
    mov  rdi, r14
    call prnuint
    mov  rdi, s_kb_nl
    call prsz

    mov  rdi, s_mem_pct
    call prsz
    mov  rdi, r15
    call prnuint
    mov  rdi, s_pct_nl
    call prsz

.sm_done:
    pop  rsi
    pop  rdi
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    ret

; =============================================================================
; show_load  –  display load averages and update threat score / v_load_lvl
; =============================================================================
show_load:
    push rsi
    push rdi
    push rcx

    mov  rdi, h_load
    call prsz
    mov  rdi, s_sep
    call prsz

    mov  rdi, p_loadavg
    call rdfile
    test rax, rax
    jz   .sl_done

    ; Print "Averages: <first line of /proc/loadavg>"
    mov  rdi, s_load_lbl
    call prsz

    xor  rcx, rcx
.sl_count:
    mov  al, [fbuf + rcx]
    cmp  al, 10
    je   .sl_print
    cmp  al, 0
    je   .sl_print
    inc  rcx
    jmp  .sl_count
.sl_print:
    mov  rdi, fbuf
    call prn
    mov  rdi, s_newline
    call prsz

    ; Parse integer part of 1-min average for threat scoring
    mov  rsi, fbuf
    call parsuint          ; rax = integer part of 1-min load

    ; Default: no load warning
    mov  byte [v_load_lvl], 0

    cmp  rax, 8
    jl   .sl_check_med
    ; Critical load  > 8 → threat +2, level 2
    mov  byte [v_load_lvl], 2
    mov  rcx, [v_threat]
    add  rcx, 2
    mov  [v_threat], rcx
    jmp  .sl_done

.sl_check_med:
    cmp  rax, 3
    jl   .sl_done
    ; Elevated load > 3 → threat +1, level 1
    mov  byte [v_load_lvl], 1
    mov  rcx, [v_threat]
    inc  rcx
    mov  [v_threat], rcx

.sl_done:
    pop  rcx
    pop  rdi
    pop  rsi
    ret

; =============================================================================
; show_net  –  display network interface statistics from /proc/net/dev
; =============================================================================
show_net:
    push rsi
    push rdi
    push rcx
    push rdx

    mov  rdi, h_net
    call prsz
    mov  rdi, s_sep
    call prsz

    mov  rdi, p_netdev
    call rdfile
    test rax, rax
    jz   .sn_done

    ; Skip the 2 header lines that /proc/net/dev always has
    mov  rsi, fbuf
    call skpln
    call skpln

    ; Print everything from here to end of buffer
    push rsi
    xor  rcx, rcx
.sn_count:
    cmp  byte [rsi + rcx], 0
    je   .sn_print
    inc  rcx
    jmp  .sn_count
.sn_print:
    pop  rdi
    call prn

.sn_done:
    pop  rdx
    pop  rcx
    pop  rdi
    pop  rsi
    ret

; =============================================================================
; show_threat  –  display threat analysis summary
; =============================================================================
show_threat:
    push r12
    push rdi

    mov  rdi, h_threat
    call prsz
    mov  rdi, s_sep
    call prsz

    mov  r12, [v_threat]

    ; ── Memory check line ────────────────────────────────────────────────────
    mov  rax, [v_mempct]
    cmp  rax, 80
    jge  .st_mem_warn
    mov  rdi, s_ok_mem
    call prsz
    jmp  .st_load_check
.st_mem_warn:
    mov  rdi, s_warn_mem
    call prsz

    ; ── Load check line ──────────────────────────────────────────────────────
.st_load_check:
    movzx rax, byte [v_load_lvl]
    test rax, rax
    jnz  .st_load_bad
    mov  rdi, s_ok_load
    call prsz
    jmp  .st_score
.st_load_bad:
    cmp  rax, 2
    jge  .st_load_crit
    mov  rdi, s_warn_load_med
    call prsz
    jmp  .st_score
.st_load_crit:
    mov  rdi, s_warn_load_hi
    call prsz

    ; ── Overall threat score ─────────────────────────────────────────────────
.st_score:
    mov  rdi, s_thr_label
    call prsz

    cmp  r12, 0
    je   .st_0
    cmp  r12, 1
    je   .st_1
    cmp  r12, 2
    je   .st_2
    mov  rdi, s_thr_3p
    call prsz
    jmp  .st_done
.st_0:
    mov  rdi, s_thr_0
    call prsz
    jmp  .st_done
.st_1:
    mov  rdi, s_thr_1
    call prsz
    jmp  .st_done
.st_2:
    mov  rdi, s_thr_2
    call prsz

.st_done:
    pop  rdi
    pop  r12
    ret

; =============================================================================
; _start  –  main entry point / refresh loop
; =============================================================================
_start:

.main_loop:
    ; Clear screen and draw banner
    mov  rdi, s_clear
    call prsz
    mov  rdi, s_banner
    call prsz

    ; Reset per-cycle accumulators
    mov  qword [v_threat],   0
    mov  byte  [v_load_lvl], 0
    mov  qword [v_mempct],   0

    ; Run each monitoring section
    call show_cpu
    call show_mem
    call show_load
    call show_net
    call show_threat

    ; Footer
    mov  rdi, s_footer
    call prsz

    ; Sleep 3 seconds
    mov  rax, SYS_NANOSLEEP
    mov  rdi, sleep_ts
    xor  rsi, rsi
    syscall

    jmp  .main_loop

    ; Unreachable – clean exit path if loop ever breaks
    mov  rax, SYS_EXIT
    xor  rdi, rdi
    syscall
