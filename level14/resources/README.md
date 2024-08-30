## Step 1: Identifying the User

We begin by checking our current user informations:

```bash
$ id
uid=2014(level14) gid=2014(level14) groups=2014(level14),100(users)
```

This shows that we are operating as the user `level14`.

---
## Step 2: Searching for Files

```bash
$ ls -la
(nothing)
```

Since no files are listed, let's check the only accessible binary, located in `/bin/getflag`. To understand how it works, we'll transfer it to our local machine for reverse engineering:
```bash
$ scp -P 4242 level14@machine_ip:/bin/getflag .
```

---
## Step 3: Reverse Engineering the Binary with Ghidra

```c
undefined4 main(void)
{
  bool bVar1;
  FILE *__stream;
  long lVar2;
  undefined4 uVar3;
  char *pcVar4;
  int iVar5;
  __uid_t _Var6;
  int iVar7;
  int in_GS_OFFSET;
  undefined local_114 [256];
  int local_14;
  
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  bVar1 = false;
  lVar2 = ptrace(PTRACE_TRACEME,0,1,0);
  if (lVar2 < 0) {
    puts("You should not reverse this");
    uVar3 = 1;
  }
  else {
    pcVar4 = getenv("LD_PRELOAD");
    if (pcVar4 == (char *)0x0) {
      iVar5 = open("/etc/ld.so.preload",0);
      if (iVar5 < 1) {
        iVar5 = syscall_open("/proc/self/maps",0);
        if (iVar5 == -1) {
          fwrite("/proc/self/maps is unaccessible, probably a LD_PRELOAD attempt exit..\n",1,0x46,
                 stderr);
          uVar3 = 1;
        }
        else {
          do {
            do {
              while( true ) {
                iVar7 = syscall_gets(local_114,0x100,iVar5);
                if (iVar7 == 0) goto LAB_08048ead;
                iVar7 = isLib(local_114,&DAT_08049063);
                if (iVar7 == 0) break;
                bVar1 = true;
              }
            } while (!bVar1);
            iVar7 = isLib(local_114,&DAT_08049068);
            if (iVar7 != 0) {
              fwrite("Check flag.Here is your token : ",1,0x20,stdout);
              _Var6 = getuid();
              __stream = stdout;
              if (_Var6 == 3006) {
                pcVar4 = (char *)ft_des("H8B8h_20B4J43><8>\\ED<;j@3");
                fputs(pcVar4,__stream);
              }
              else if (_Var6 < 0xbbf) {
                if (_Var6 == 0xbba) {
                  pcVar4 = (char *)ft_des("<>B16\\AD<C6,G_<1>^7ci>l4B");
                  fputs(pcVar4,__stream);
                }
                else if (_Var6 < 0xbbb) {
                  if (_Var6 == 3000) {
                    pcVar4 = (char *)ft_des("I`fA>_88eEd:=`85h0D8HE>,D");
                    fputs(pcVar4,__stream);
                  }
                  else if (_Var6 < 0xbb9) {
                    if (_Var6 == 0) {
                      fwrite("You are root are you that dumb ?\n",1,0x21,stdout);
                    }
                    else {
LAB_08048e06:
                      fwrite("\nNope there is no token here for you sorry. Try again :)",1,0x38,
                             stdout);
                    }
                  }
                  else {
                    pcVar4 = (char *)ft_des("7`4Ci4=^d=J,?>i;6,7d416,7");
                    fputs(pcVar4,__stream);
                  }
                }
                else if (_Var6 == 0xbbc) {
                  pcVar4 = (char *)ft_des("?4d@:,C>8C60G>8:h:Gb4?l,A");
                  fputs(pcVar4,__stream);
                }
                else if (_Var6 < 3005) {
                  pcVar4 = (char *)ft_des("B8b:6,3fj7:,;bh>D@>8i:6@D");
                  fputs(pcVar4,__stream);
                }
                else {
                  pcVar4 = (char *)ft_des("G8H.6,=4k5J0<cd/D@>>B:>:4");
                  fputs(pcVar4,__stream);
                }
              }
              else if (_Var6 == 0xbc2) {
                pcVar4 = (char *)ft_des("74H9D^3ed7k05445J0E4e;Da4");
                fputs(pcVar4,__stream);
              }
              else if (_Var6 < 0xbc3) {
                if (_Var6 == 0xbc0) {
                  pcVar4 = (char *)ft_des("bci`mC{)jxkn<\"uD~6%g7FK`7");
                  fputs(pcVar4,__stream);
                }
                else if (_Var6 < 3009) {
                  pcVar4 = (char *)ft_des("78H:J4<4<9i_I4k0J^5>B1j`9");
                  fputs(pcVar4,__stream);
                }
                else {
                  pcVar4 = (char *)ft_des("Dc6m~;}f8Cj#xFkel;#&ycfbK");
                  fputs(pcVar4,__stream);
                }
              }
              else if (_Var6 == 3012) {
                pcVar4 = (char *)ft_des("8_Dw\"4#?+3i]q&;p6 gtw88EC");
                fputs(pcVar4,__stream);
              }
              else if (_Var6 < 3012) {
                pcVar4 = (char *)ft_des("70hCi,E44Df[A4B/J@3f<=:`D");
                fputs(pcVar4,__stream);
              }
              else if (_Var6 == 3013) {
                pcVar4 = (char *)ft_des("boe]!ai0FB@.:|L6l@A?>qJ}I");
                fputs(pcVar4,__stream);
              }
              else {
                if (_Var6 != 0xbc6) goto LAB_08048e06;
                pcVar4 = (char *)ft_des("g <t61:|4_|!@IF.-62FH&G~DCK/Ekrvvdwz?v|");
                fputs(pcVar4,__stream);
              }
              fputc(10,stdout);
              goto LAB_08048ead;
            }
            iVar7 = afterSubstr(local_114,"00000000 00:00 0");
          } while (iVar7 != 0);
          fwrite("LD_PRELOAD detected through memory maps exit ..\n",1,0x30,stderr);
LAB_08048ead:
          uVar3 = 0;
        }
      }
      else {
        fwrite("Injection Linked lib detected exit..\n",1,0x25,stderr);
        uVar3 = 1;
      }
    }
    else {
      fwrite("Injection Linked lib detected exit..\n",1,0x25,stderr);
      uVar3 = 1;
    }
  }
  if (local_14 == *(int *)(in_GS_OFFSET + 0x14)) {
    return uVar3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

### Explanation
As in the previous exercise, the `ft_des` function is present, and we have therefore accessed all the passwords
`flag` users.

## Step 4: Re-compile the source code
We can now re-compile the `ft_des` function, passing in the encrypted string from the binary to obtain the decrypted flag. Here’s the recompiled code:

```c
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

char * ft_des(char *param_1)
{
  char cVar1;
  char *pcVar2;
  unsigned int uVar3;
  char *pcVar4;
  unsigned char bVar5;
  unsigned int local_20;
  int local_1c;
  int local_18;
  int local_14;
  
  bVar5 = 0;
  pcVar2 = strdup(param_1);
  local_1c = 0;
  local_20 = 0;
  do {
    uVar3 = 0xffffffff;
    pcVar4 = pcVar2;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + (unsigned int)bVar5 * -2 + 1;
    } while (cVar1 != '\0');
    if (~uVar3 - 1 <= local_20) {
      return pcVar2;
    }
    if (local_1c == 6) {
      local_1c = 0;
    }
    if ((local_20 & 1) == 0) {
      if ((local_20 & 1) == 0) {
        for (local_14 = 0; local_14 < "0123456"[local_1c]; local_14 = local_14 + 1) {
          pcVar2[local_20] = pcVar2[local_20] + -1;
          if (pcVar2[local_20] == '\x1f') {
            pcVar2[local_20] = '~';
          }
        }
      }
    }
    else {
      for (local_18 = 0; local_18 < "0123456"[local_1c]; local_18 = local_18 + 1) {
        pcVar2[local_20] = pcVar2[local_20] + '\x01';
        if (pcVar2[local_20] == '\x7f') {
          pcVar2[local_20] = ' ';
        }
      }
    }
    local_20 = local_20 + 1;
    local_1c = local_1c + 1;
  } while( true );
}

int main(void) {

    char *token = ft_des("g <t61:|4_|!@IF.-62FH&G~DCK/Ekrvvdwz?v|");
    printf("%s\n", token);
}
```

```bash
7QiHafiNa3HVozsaXkawuYrTstxbpABHD8CPnHJ
```

```bash
$ su flag14
Password: 7QiHafiNa3HVozsaXkawuYrTstxbpABHD8CPnHJ

% getflag
Check flag.Here is your token : 7QiHafiNa3HVozsaXkawuYrTstxbpABHD8CPnHJ
```

---

And there you have it, the token is `7QiHafiNa3HVozsaXkawuYrTstxbpABHD8CPnHJ`.