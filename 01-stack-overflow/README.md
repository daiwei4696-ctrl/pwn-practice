# 01 · 栈溢出：ret2text

同一漏洞模式的最短路径演示，重点不是拿 shell（那很容易），而是**搞清为什么"明明跳到 win() 了却崩"**。

**核心结论**：`pad72 + ret + win` 才能通；`pad72 + win` 会 SIGSEGV 在
`do_system+363: movaps XMMWORD PTR [rsp+0x50],xmm0`——典型的 16 字节栈对齐违例。

完整报告见 [`report.md`](report.md)。

## 快速开始
```bash
cd 01-stack-overflow
bash build.sh
python3 exp_ret2text.py     # 输出 uid=1001(lzq)
```

## 覆盖的 M3 要求
- [x] ret2text → `report.md` §2.6
- [x] cyclic 定偏移 → `evidence/cyclic-offset.txt`（gdb 断点实测 + cyclic_find = 72）
- [x] 64 位栈对齐 ret gadget → `evidence/gdb-alignment-proof.txt`、`evidence/align-experiment.log`

## 一句话经验
> 栈对齐不是玄学垫片：垫 1 个 ret 通，垫 0 个和 2 个都崩。按 16 取模算，别试。