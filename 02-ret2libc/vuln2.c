/* 练习 02 · ret2libc 完整泄露链
 *
 * 与 01 完全相同的漏洞模式：read(STDIN_FILENO, buf, 256) 读进 char buf[64]。
 * 区别（把 ret2text 的路全堵死，只留 ret2libc 一条路）：
 *   1. 没有 win()          —— 二进制里没有任何一句现成的 shell 代码
 *   2. 编译不加 -z execstack —— NX 开启，栈不可执行，shellcode 路线堵死
 *   3. 显式保留 pop rdi; ret —— 真实 CTF 题的 gadget 来自大型代码的指令片段，
 *      这里为了专注学习 ROP 链本身，用内联汇编单独写出来（非 static，保证被编译进 .text）
 *
 * 利用链：puts(puts@got) 泄露 libc 地址 → 反查 libc 基址 →
 *         ret(对齐) + pop rdi; "/bin/sh" + system → shell
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* 显式 gadget：真实题目里 pop rdi; ret 这类指令片段随处可见，这里单独写出来便于定位 */
void pop_rdi_ret(void)
{
    __asm__ volatile ("pop %rdi\n\tret\n");
}

void vuln(void)
{
    char buf[64];

    printf("input> ");
    fflush(stdout);
    read(STDIN_FILENO, buf, 256);   /* <-- 漏洞点：256 字节读进 64 字节栈缓冲 */
    printf("you said: %s\n", buf);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
    puts("[*] ret2libc practice: no win(), NX on, only one tiny gadget");
    vuln();
    puts("bye");
    return 0;
}