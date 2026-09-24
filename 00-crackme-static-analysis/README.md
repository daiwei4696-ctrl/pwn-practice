# 00 · crackme 静态分析（Ghidra + radare2）

用两个独立工具交叉分析一个自编小 crackme，完整走一遍
「strings 提假设 → objdump 证实面 → radare2 定位 → Ghidra 伪码 → 动态终验」的流程。

**结论**：口令 `S3cr3t!`，明文字面量 `strcmp` 全等比较，无混淆、无反调试。
完整四段式报告见 [`report.md`](report.md)。

## 快速开始
```bash
cd 00-crackme-static-analysis
gcc -O0 -no-pie crackme.c -o crackme
echo "S3cr3t!" | ./crackme        # -> pw: yes
echo "wrong"   | ./crackme        # -> pw: no

r2 -q -c "aaa; s sym.check; pdf" crackme
```

## 覆盖的 M3 要求
- [x] Ghidra / radare2 完整分析一个小 crackme → `report.md`
- [x] 规范报告（scope / 证据 / 结论 / 复现 四段式）→ `report.md`
- [x] 每个结论都挂证据 → 报告结论表 C1–C5 逐条标注证据编号

## 证据目录
`evidence/` 下 8 份原始输出，报告中每条引用都可回溯到具体行号。