# M3 · 00 — crackme 静态分析报告

> 分析对象：`crackme`（16056 字节，本仓库自编译教学样本）
> 工具链：Ghidra 12.1.4（headless）+ radare2 + objdump + strings
> 分析日期：2026-09-24
> 报告遵循四段式：**范围 → 证据 → 结论 → 复现**，每个结论后括注证据文件编号。

---

## 1. 范围（Scope）

| 项 | 内容 |
|---|---|
| 样本来源 | 本仓库 `crackme.c` 自行编译，**不来自任何第三方/真实恶意样本**，仅用于练习静态分析流程 |
| 样本指纹 | md5 `087151029fa5219d7fe6b41e9b98463e`（`evidence/00-file-checksec.txt`） |
| 平台 | ELF 64-bit LSB executable, x86-64, GNU/Linux，No PIE，未剥离符号（`evidence/00-file-checksec.txt`） |
| 分析目标 | ① 定位校验逻辑 ② 提取正确口令 ③ 说明每条口令结论由哪个工具的哪个证据支撑 |
| 工具合法性 | Ghidra / radare2 / objdump / strings 均为本机已安装工具，全程只做静态分析 + 一次本地动态运行，未联网 |

**免责说明**：本样本与所有分析产物均为本人构建，用于验证"读代码 → 提口令"的标准流程，不涉及对他人系统的任何测试。

---

## 2. 证据（Evidence）

### 2.1 文件层面的第一眼 — `strings`
`evidence/01-strings.txt` 第 `2004` 行直接给出一个高位可疑字符串：

```
   2004 S3cr3t!
```

同时可见导入函数 `strcmp`（`4a6`）、`__isoc99_scanf`（`497`）、`puts`（`479`），以及格式串 `%63s`（`2011`）和输出字符串 `yes` / `no`。

> **初步假设（尚未证实）**：程序用 `scanf("%63s")` 读输入，用 `strcmp` 与 `"S3cr3t!"` 比较，成功/失败分别打印 `yes` / `no`。
> 假设必须靠反汇编/反编译证实，不能只凭 strings 下结论。

### 2.2 `.rodata` 原始字节 — `objdump -s -j .rodata`
`evidence/03-rodata-hex.txt`：

```
 402000 01000200 53336372 33742100 70773a20  ....S3cr3t!.pw: 
 402010 00253633 73007965 73006e6f 00        .%63s.yes.no.
```

`53 33 63 72 33 37 74 21` 正是 ASCII `S3cr3t!`，且其后紧跟 `00`——说明它是**以 NUL 结尾的完整字面量**，而不是某个更长字符串的中间片段。地址 `0x402004`。

### 2.3 函数清单与调用图 — `radare2`
`evidence/05-r2-afl.txt`（`afl`）：

```
0x004011c6    7 118          main
0x00401196    1 48           sym.check
0x00401090    1 10           sym.imp.strcmp
0x004010a0    1 10           sym.imp.__isoc99_scanf
```

二进制里只有 `main` 和 `check` 两个自定义函数，规模 118 / 48 字节——这是一次典型的"小 crackme"静态分析。

### 2.4 check() 反汇编 — `radare2 pdf`
`evidence/04-r2-pdf-check.txt`（`aaa; s sym.check; pdf`）：

```
0x004011a6      mov rax, qword [s1]
0x004011aa      lea rdx, str.S3cr3t_        ; 0x402004 ; "S3cr3t!"
0x004011b1      mov rsi, rdx                ; const char *s2
0x004011b4      mov rdi, rax                ; const char *s1
0x004011b7      call sym.imp.strcmp         ; int strcmp(const char *s1, const char *s2)
0x004011bc      test eax, eax
0x004011be      sete al
0x004011c1      movzx eax, al
0x004011c4      leave
0x004011c5      ret
```

radare2 直接把 `0x402004` 标注为 `str.S3cr3t_`，并把 `strcmp` 的两个参数名反标为 `s1`/`s2`。

### 2.5 main() 反汇编 — `radare2 pdf`
`evidence/06-r2-pdf-main.txt`（`aaa; s main; pdf`）显示 `main` 内：
- `lea rax, str.pw_` → `printf` 打印 `"pw: "`
- `lea rax, [format]`（`%63s`）→ `__isoc99_scanf`，目标 `lea rdx, [rbp-0x40]`（64 字节栈缓冲）
- 读入后 `call sym.check`

### 2.6 Ghidra 反编译
`evidence/ghidra-decomp.c` 中 `check` 与 `main`：

```c
bool check(char *param_1)
{
  int iVar1;
  iVar1 = strcmp(param_1,"S3cr3t!");
  return iVar1 == 0;
}

undefined8 main(void)
{
  ...
  undefined1 local_48 [64];
  printf("pw: ");
  iVar1 = __isoc99_scanf(&DAT_00402011,local_48);
  if (iVar1 == 1) {
    iVar1 = check(local_48);
    if (iVar1 == 0) { __s = "no"; } else { __s = "yes"; }
    puts(__s);
    ...
```

Ghidra 独立给出的伪代码与 radare2 反汇编结论完全一致，**两个工具交叉验证通过**。

### 2.7 动态验证（本地）
在 WSL Ubuntu-24.04 直接运行（见 §4），输入 `S3cr3t!` 输出 `yes`，输入其它值输出 `no`。这是对静态结论的最终确认。

---

## 3. 结论（Conclusion）

| # | 结论 | 支撑证据 |
|---|---|---|
| C1 | 程序流程为：打印 `pw: ` → `scanf("%63s", buf)` → `check(buf)` → 按结果 `puts("yes"/"no")` | 2.3 函数清单 + 2.5 main 反汇编 + 2.6 Ghidra 伪码 |
| C2 | 校验方式是**与固定字面量 `"S3cr3t!"` 做 `strcmp` 全等比较**，无长度/编码变换、无逐字符 XOR/移位/哈希 | 2.4 `call strcmp` + `test eax,eax; sete al` + 2.6 `return iVar1 == 0` |
| C3 | **正确口令为 `S3cr3t!`**（8 个字符，含大写 S、数字 3、小写 e、感叹号） | 2.1 strings `S3cr3t!` + 2.2 `.rodata` NUL 结尾字面量 + 2.4 radare2 标注 `str.S3cr3t_` + 2.7 动态 `yes` |
| C4 | 输入用 `%63s` 限制到 63 字符 + NUL，落在 `char buf[64]` 内，**本样本无栈溢出** | 2.6 Ghidra `local_48 [64]` 与 `scanf("%63s", ...)` 配对 |
| C5 | 口令判定是明文、可静态提取的，无任何混淆/反调试/加壳 | 2.1–2.6 全部证据一致，且二进制未剥离、未加壳（`Stripped: No`）|

**方法学结论**：strings 给出假设 → objdump `.rodata` 确认字面量完整性 → radare2 定位调用点与参数 → Ghidra 交叉验证伪码 → 动态运行终验。五个环节互相印证，任何单点都不能单独作为结论——这正是"每个结论都挂证据"的要求。

---

## 4. 复现（Reproduction）

### 4.1 编译（在 WSL Ubuntu-24.04 中）
```bash
cd practice/pwn-practice/00-crackme-static-analysis
gcc -O0 -no-pie crackme.c -o crackme
```

### 4.2 静态分析命令
```bash
# 工具 1：radare2
r2 -q -c "aaa; s sym.check; pdf" crackme     # 对应 evidence/04-r2-pdf-check.txt
r2 -q -c "aaa; afl"            crackme       # 对应 evidence/05-r2-afl.txt
r2 -q -c "aaa; s main; pdf"     crackme       # 对应 evidence/06-r2-pdf-main.txt

# 工具 2：objdump
strings -a -t x crackme                      # 对应 evidence/01-strings.txt
objdump -s -j .rodata crackme                # 对应 evidence/03-rodata-hex.txt

# 工具 3：Ghidra headless（中文路径须经 ASCII junction 中转）
$env:JAVA_HOME = "D:\Java\jdk-21.0.2"
& "D:\ghidra-test\support\analyzeHeadless.bat" <projdir> crackme `
    -import "D:\m3test\crackme" -scriptPath "D:\m3test\scripts" `
    -postScript DecompileAll.java D:/m3test/ghidra-crackme.c
```

### 4.3 动态终验
```bash
echo "S3cr3t!" | ./crackme      # 期望输出: pw: yes
echo "wrong"   | ./crackme      # 期望输出: pw: no
```

---

## 5. 文件清单
```
00-crackme-static-analysis/
├── crackme.c                        # 教学样本源码（本人编写）
├── crackme                          # 编译产物
├── report.md                        # 本报告
└── evidence/
    ├── 00-file-checksec.txt         # file / md5 / checksec
    ├── 01-strings.txt               # strings -a -t x
    ├── 02-objdump-disasm.txt        # objdump -d -M intel 全量
    ├── 03-rodata-hex.txt            # objdump -s -j .rodata（口令字面量证据）
    ├── 04-r2-pdf-check.txt          # radare2 check() 反汇编
    ├── 05-r2-afl.txt                # radare2 函数清单
    ├── 06-r2-pdf-main.txt           # radare2 main() 反汇编
    └── ghidra-decomp.c              # Ghidra headless 全函数反编译
```