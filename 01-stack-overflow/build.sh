#!/usr/bin/env bash
# 练习 01 编译脚本：参数与报告中"证据"一节一一对应
set -e
cd "$(dirname "$0")"
gcc -O0 -no-pie -fno-stack-protector -z execstack vuln.c -o vuln
echo "[+] built:"
file vuln
