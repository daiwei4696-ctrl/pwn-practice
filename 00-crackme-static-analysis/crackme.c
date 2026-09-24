#include <stdio.h>
#include <string.h>

int check(char *s)
{
    return strcmp(s, "S3cr3t!") == 0;
}

int main(void)
{
    char buf[64];
    printf("pw: ");
    if (scanf("%63s", buf) != 1) return 1;
    puts(check(buf) ? "yes" : "no");
    return 0;
}
