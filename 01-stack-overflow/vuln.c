/* 练习 01 · 栈溢出入门（ret2text + ret2libc）
 * 编译参数见 build.sh：
 *   gcc -O0 -no-pie -fno-stack-protector -z execstack vuln.c -o vuln
 * 故意保留三个"错误"：read() 一次读 256 字节进 64 字节栈缓冲、无边界检查、win() 直接 system()
 * 说明：Ubuntu 24.04(glibc 2.39) 已不再声明 gets()，故用 read() 达到同样的无界读效果。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win(void)
{
    puts("[*] win() reached");
    fflush(stdout);
    system("/bin/sh");
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
    vuln();
    puts("bye");
    return 0;
}
