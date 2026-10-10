# pwn-practice — M3 栈溢出与 ret2libc 实战记录

本仓库是「逆向 12 个月计划」**M3 阶段**的练习成果，包含一道静态分析题和两道栈溢出题。
所有靶机均由本人编写编译，仅用于学习，**未对任何第三方系统进行测试**。

## 目录

| 目录 | 内容 | 核心技术 |
|---|---|---|
| [`00-crackme-static-analysis/`](00-crackme-static-analysis/) | Ghidra + radare2 交叉分析小 crackme | 四段式分析报告、双工具互证 |
| [`01-stack-overflow/`](01-stack-overflow/) | ret2text 拿 shell | cyclic 定偏移、**64 位栈对齐**、gdb 抓 `movaps` SIGSEGV |
| [`02-ret2libc/`](02-ret2libc/) | ret2libc 完整泄露链 | libc 泄露与反查、ROP 链、本地/远程双模式 |
| [`Writeup-04-ret2libc.md`](Writeup-04-ret2libc.md) | 作品集 #4：ret2libc 从本地到远程 | 栈对齐"数两次"法则、BuildID 反查 |

## 报告规范（M3 验收要求）

每题的报告统一采用四段式，且**每个结论都挂证据**：

```
1. 范围 Scope      —— 样本来源、指纹、缓解措施、分析边界
2. 证据 Evidence   —— 工具 + 命令 + 原始输出，可回溯到具体行号
3. 结论 Conclusion —— 编号列表，每条注明支撑证据编号
4. 复现 Reproduction —— 可照抄执行的命令序列
```

`evidence/` 目录保存所有工具的原始输出（checksec / nm / objdump / radare2 / ROPgadget / gdb / 运行日志），
报告中每处引用都能在 `evidence/` 里找到对应文件。

## 环境

- WSL Ubuntu 24.04（gcc 13.3.0，glibc 2.39，gdb 15.1 + pwndbg）
- pwntools（`~/.local/bin`，Python 3.12）
- Ghidra 12.1.4 headless（Windows 侧，中文路径须经 ASCII junction 中转）
- radare2

## 三个最值得记住的坑

1. **栈对齐是硬门槛，不是优化**。`pad72+win` 直接崩，`pad72+ret+win` 才通，
   `pad72+ret+ret+win` 又崩。按 16 取模算，别靠试。
   → `01-stack-overflow/evidence/gdb-alignment-proof.txt`
2. **每重入一次漏洞函数，就重数一次栈对齐**。`call` 进 `vuln` 和 ROP `ret` 进 `vuln`
   的对齐状态不同，所以 02 的 stage2 要垫两个 `ret`。
   → `02-ret2libc/report.md` §3.4
3. **Ghidra 12.x 不要直接吃中文路径**。复制到 ASCII 路径再 `-import` 即可。
   → `02-ret2libc/report.md` §3.1