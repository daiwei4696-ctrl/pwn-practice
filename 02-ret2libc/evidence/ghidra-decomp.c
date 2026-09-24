/* program: vuln2 */
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



/* ===== puts @ 00401080 ===== */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int puts(char *__s)

{
  int iVar1;
  
  iVar1 = puts(__s);
  return iVar1;
}



/* ===== printf @ 00401090 ===== */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int printf(char *__format,...)

{
  int iVar1;
  
  iVar1 = printf(__format);
  return iVar1;
}



/* ===== read @ 004010a0 ===== */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

ssize_t read(int __fd,void *__buf,size_t __nbytes)

{
  ssize_t sVar1;
  
  sVar1 = read(__fd,__buf,__nbytes);
  return sVar1;
}



/* ===== fflush @ 004010b0 ===== */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int fflush(FILE *__stream)

{
  int iVar1;
  
  iVar1 = fflush(__stream);
  return iVar1;
}



/* ===== setvbuf @ 004010c0 ===== */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int setvbuf(FILE *__stream,char *__buf,int __modes,size_t __n)

{
  int iVar1;
  
  iVar1 = setvbuf(__stream,__buf,__modes,__n);
  return iVar1;
}



/* ===== _start @ 004010d0 ===== */

void processEntry _start(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  __libc_start_main(main,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



/* ===== _dl_relocate_static_pie @ 00401100 ===== */

void _dl_relocate_static_pie(void)

{
  return;
}



/* ===== deregister_tm_clones @ 00401110 ===== */

/* WARNING: Removing unreachable block (ram,0x0040111d) */
/* WARNING: Removing unreachable block (ram,0x00401127) */

void deregister_tm_clones(void)

{
  return;
}



/* ===== register_tm_clones @ 00401140 ===== */

/* WARNING: Removing unreachable block (ram,0x0040115f) */
/* WARNING: Removing unreachable block (ram,0x00401169) */

void register_tm_clones(void)

{
  return;
}



/* ===== __do_global_dtors_aux @ 00401180 ===== */

void __do_global_dtors_aux(void)

{
  if (completed_0 == '\0') {
    deregister_tm_clones();
    completed_0 = 1;
    return;
  }
  return;
}



/* ===== frame_dummy @ 004011b0 ===== */

void frame_dummy(void)

{
  register_tm_clones();
  return;
}



/* ===== pop_rdi_ret @ 004011b6 ===== */

void pop_rdi_ret(void)

{
  return;
}



/* ===== vuln @ 004011c3 ===== */

void vuln(void)

{
  undefined1 local_48 [64];
  
  printf("input> ");
  fflush(stdout);
  read(0,local_48,0x100);
  printf("you said: %s\n",local_48);
  return;
}



/* ===== main @ 00401226 ===== */

undefined8 main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  puts("[*] ret2libc practice: no win(), NX on, only one tiny gadget");
  vuln();
  puts("bye");
  return 0;
}



/* ===== _fini @ 00401294 ===== */

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



/* ===== printf @ 00405010 ===== */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int printf(char *__format,...)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* printf@GLIBC_2.2.5 */
  halt_baddata();
}



/* ===== read @ 00405018 ===== */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

ssize_t read(int __fd,void *__buf,size_t __nbytes)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* read@GLIBC_2.2.5 */
  halt_baddata();
}



/* ===== __gmon_start__ @ 00405020 ===== */

/* WARNING: Control flow encountered bad instruction data */

void __gmon_start__(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== fflush @ 00405028 ===== */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int fflush(FILE *__stream)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* fflush@GLIBC_2.2.5 */
  halt_baddata();
}



/* ===== setvbuf @ 00405030 ===== */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int setvbuf(FILE *__stream,char *__buf,int __modes,size_t __n)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* setvbuf@GLIBC_2.2.5 */
  halt_baddata();
}



