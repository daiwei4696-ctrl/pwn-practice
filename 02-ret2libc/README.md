# 02 · ret2libc：从本地到远程

NX 开启、无后门函数，只剩 ret2libc 一条路。完整走
「泄露 libc → 反查基址 → 二次进漏洞 → ROP 拿 shell」，本地与 socket 远程双模式验证。

**核心结论**：stage2 需要垫 **2 个** `ret`——不是因为"多垫总没错"，
而是因为 stage1 用 `ret` 跳回 `vuln` 会让栈对齐状态翻转，必须先用一个 `ret` 补回来。

完整报告（Writeup #4 雏形）见 [`report.md`](report.md)。

## 快速开始
```bash
cd 02-ret2libc
bash build.sh

# 本地
python3 exp_ret2libc.py

# 远程（两个终端，或后台起 serve）
python3 serve.py 9999 &
python3 exp_ret2libc.py remote
```

## 覆盖的 M3 要求
- [x] ret2libc 全链 → `report.md` §4
- [x] 64 位栈对齐 ret gadget（且是"两个"）→ `report.md` §3.4
- [x] libc-database 反查思路（BuildID + `readelf -sW`）→ `evidence/07-libc-offsets.txt`
- [x] 远程利用（socket）→ `evidence/exp-ret2libc-remote-run.log`

## 一句话经验
> 每用 ROP 重入一次漏洞函数，就重新数一次栈对齐。第二次进 `vuln` 时它是 `ret` 进来的，不是 `call`。