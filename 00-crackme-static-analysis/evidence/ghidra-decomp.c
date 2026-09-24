/* program: crackme */
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



/* ===== puts @ 00401070 ===== */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int puts(char *__s)

{
  int iVar1;
  
  iVar1 = puts(__s);
  return iVar1;
}



/* ===== printf @ 00401080 ===== */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int printf(char *__format,...)

{
  int iVar1;
  
  iVar1 = printf(__format);
  return iVar1;
}



/* ===== strcmp @ 00401090 ===== */

/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int strcmp(char *__s1,char *__s2)

{
  int iVar1;
  
  iVar1 = strcmp(__s1,__s2);
  return iVar1;
}



/* ===== __isoc99_scanf @ 004010a0 ===== */

void __isoc99_scanf(void)

{
  __isoc99_scanf();
  return;
}



/* ===== _start @ 004010b0 ===== */

void processEntry _start(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  __libc_start_main(main,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



/* ===== _dl_relocate_static_pie @ 004010e0 ===== */

void _dl_relocate_static_pie(void)

{
  return;
}



/* ===== deregister_tm_clones @ 004010f0 ===== */

/* WARNING: Removing unreachable block (ram,0x004010fd) */
/* WARNING: Removing unreachable block (ram,0x00401107) */

void deregister_tm_clones(void)

{
  return;
}



/* ===== register_tm_clones @ 00401120 ===== */

/* WARNING: Removing unreachable block (ram,0x0040113f) */
/* WARNING: Removing unreachable block (ram,0x00401149) */

void register_tm_clones(void)

{
  return;
}



/* ===== __do_global_dtors_aux @ 00401160 ===== */

void __do_global_dtors_aux(void)

{
  if (completed_0 == '\0') {
    deregister_tm_clones();
    completed_0 = 1;
    return;
  }
  return;
}



/* ===== frame_dummy @ 00401190 ===== */

void frame_dummy(void)

{
  register_tm_clones();
  return;
}



/* ===== check @ 00401196 ===== */

bool check(char *param_1)

{
  int iVar1;
  
  iVar1 = strcmp(param_1,"S3cr3t!");
  return iVar1 == 0;
}



/* ===== main @ 004011c6 ===== */

undefined8 main(void)

{
  int iVar1;
  undefined8 uVar2;
  char *__s;
  undefined1 local_48 [64];
  
  printf("pw: ");
  iVar1 = __isoc99_scanf(&DAT_00402011,local_48);
  if (iVar1 == 1) {
    iVar1 = check(local_48);
    if (iVar1 == 0) {
      __s = "no";
    }
    else {
      __s = "yes";
    }
    puts(__s);
    uVar2 = 0;
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}



/* ===== _fini @ 0040123c ===== */

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



/* ===== strcmp @ 00405018 ===== */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

int strcmp(char *__s1,char *__s2)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* strcmp@GLIBC_2.2.5 */
  halt_baddata();
}



/* ===== __gmon_start__ @ 00405020 ===== */

/* WARNING: Control flow encountered bad instruction data */

void __gmon_start__(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== __isoc99_scanf @ 00405028 ===== */

/* WARNING: Control flow encountered bad instruction data */

void __isoc99_scanf(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
                    /* __isoc99_scanf@GLIBC_2.7 */
  halt_baddata();
}



