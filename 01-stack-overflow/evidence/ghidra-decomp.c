/* program: vuln */
/* ===== _init @ 00401000 ===== */

int _init(EVP_PKEY_CTX *ctx)

{
  int iVar1;
  
  iVar1 = __gmon_start__();
  return iVar1;
}



/* ===== FUN_00401020 @ 00401020 ===== */

void FUN_00401020(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}



/* ===== puts @ 00401090 ===== */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int puts(char *__s)

{
  int iVar1;
  
  iVar1 = puts(__s);
  return iVar1;
}



/* ===== system @ 004010a0 ===== */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int system(char *__command)

{
  int iVar1;
  
  iVar1 = system(__command);
  return iVar1;
}



/* ===== printf @ 004010b0 ===== */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int printf(char *__format,...)

{
  int iVar1;
  
  iVar1 = printf(__format);
  return iVar1;
}



/* ===== read @ 004010c0 ===== */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

ssize_t read(int __fd,void *__buf,size_t __nbytes)

{
  ssize_t sVar1;
  
  sVar1 = read(__fd,__buf,__nbytes);
  return sVar1;
}



/* ===== fflush @ 004010d0 ===== */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int fflush(FILE *__stream)

{
  int iVar1;
  
  iVar1 = fflush(__stream);
  return iVar1;
}



/* ===== setvbuf @ 004010e0 ===== */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int setvbuf(FILE *__stream,char *__buf,int __modes,size_t __n)

{
  int iVar1;
  
  iVar1 = setvbuf(__stream,__buf,__modes,__n);
  return iVar1;
}



/* ===== _start @ 004010f0 ===== */

void processEntry _start(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  __libc_start_main(main,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



/* ===== _dl_relocate_static_pie @ 00401120 ===== */

void _dl_relocate_static_pie(void)

{
  return;
}



/* ===== deregister_tm_clones @ 00401130 ===== */

/* WARNING: Removing unreachable block (ram,0x0040113d) */
/* WARNING: Removing unreachable block (ram,0x00401147) */

void deregister_tm_clones(void)

{
  return;
}



/* ===== register_tm_clones @ 00401160 ===== */

/* WARNING: Removing unreachable block (ram,0x0040117f) */
/* WARNING: Removing unreachable block (ram,0x00401189) */

void register_tm_clones(void)

{
  return;
}



/* ===== __do_global_dtors_aux @ 004011a0 ===== */

void __do_global_dtors_aux(void)

{
  if (completed_0 == '\0') {
    deregister_tm_clones();
    completed_0 = 1;
    return;
  }
  return;
}



/* ===== frame_dummy @ 004011d0 ===== */

void frame_dummy(void)

{
  register_tm_clones();
  return;
}



/* ===== win @ 004011d6 ===== */

void win(void)

{
  puts("[*] win() reached");
  fflush(stdout);
  system("/bin/sh");
  return;
}



/* ===== vuln @ 0040120e ===== */

void vuln(void)

{
  undefined1 local_48 [64];
  
  printf("input> ");
  fflush(stdout);
  read(0,local_48,0x100);
  printf("you said: %s\n",local_48);
  return;
}



/* ===== main @ 00401271 ===== */

undefined8 main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  vuln();
  puts("bye");
  return 0;
}



/* ===== _fini @ 004012d0 ===== */

void _fini(void)

{
  return;
}



/* ===== __libc_start_main @ 00405000 ===== */

/* WARNING: Control flow encountered bad instruction data */

void __libc_start_main(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* __libc_start_main@GLIBC_2.34 */
  halt_baddata();
}



/* ===== puts @ 00405008 ===== */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int puts(char *__s)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* puts@GLIBC_2.2.5 */
  halt_baddata();
}



/* ===== system @ 00405010 ===== */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int system(char *__command)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* system@GLIBC_2.2.5 */
  halt_baddata();
}



/* ===== printf @ 00405018 ===== */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int printf(char *__format,...)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* printf@GLIBC_2.2.5 */
  halt_baddata();
}



/* ===== read @ 00405020 ===== */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

ssize_t read(int __fd,void *__buf,size_t __nbytes)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* read@GLIBC_2.2.5 */
  halt_baddata();
}



/* ===== __gmon_start__ @ 00405028 ===== */

/* WARNING: Control flow encountered bad instruction data */

void __gmon_start__(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== fflush @ 00405030 ===== */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int fflush(FILE *__stream)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* fflush@GLIBC_2.2.5 */
  halt_baddata();
}



/* ===== setvbuf @ 00405038 ===== */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int setvbuf(FILE *__stream,char *__buf,int __modes,size_t __n)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* setvbuf@GLIBC_2.2.5 */
  halt_baddata();
}



