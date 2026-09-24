#!/usr/bin/env bash
# 练习 02 编译脚本：注意与 01 的差异 —— 故意不加 -z execstack（NX 保持开启）
set -e
cd "$(dirname "$0")"
gcc -O0 -no-pie -fno-stack-protector vuln2.c -o vuln2
echo "[+] built:"
file vuln2