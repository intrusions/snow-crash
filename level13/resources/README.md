## Step 1: Identifying the User

We begin by checking our current user informations:

```bash
$ id
uid=2013(level13) gid=2013(level13) groups=2013(level13),100(users)
```

This shows that we are operating as the user `level13`.

---
## Step 2: Searching for Files

```bash
$ ls -la
-rwsr-sr-x 1 flag13  level13 7303 Aug 30  2015 level13

$ file level13
level13: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xde91cfbf70ca6632d7e4122f8210985dea778605, not stripped
```
The level13 is a setuid ELF executable, meaning it executes with flag13 user's privileges.

Let's transfer it to our local machine for reverse engineering:
```bash
$ scp -P 4242 level13@machine_ip:/home/level13/level13 .
```

---
## Step 3: Reverse Engineering the Binary with Ghidra

```c
char * ft_des(char *param_1)
{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  char *pcVar4;
  byte bVar5;
  uint local_20;
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
      pcVar4 = pcVar4 + (uint)bVar5 * -2 + 1;
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

void main(void)
{
  __uid_t _Var1;
  undefined4 uVar2;
  
  _Var1 = getuid();
  if (_Var1 != 0x1092) {
    _Var1 = getuid();
    printf("UID %d started us but we we expect %d\n",_Var1,0x1092);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  uVar2 = ft_des("boe]!ai0FB@.:|L6l@A?>qJ}I");
  printf("your token is %s\n",uVar2);
  return;
}
```

### Explanation
Main Function: The main function checks if the program is being executed by a user with a specific UID (0x1092 in hexadecimal, which equals 4242 in decimal). If the UID does not match, the program prints an error and exits.

ft_des Function: The ft_des function appears to perform some transformation on a string (in this case, `boe]!ai0FB@.:|L6l@A?>qJ}I`). The function manipulates each character of the input string according to certain rules.

## Step 4: Re-compile the source code
To bypass the UID check, we can modify and recompile the source code. Here is the modified version:

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

    char *token = ft_des("boe]!ai0FB@.:|L6l@A?>qJ}I");
    printf("%s\n", token);
}
```

```bash
2A31L79asukciNyi8uppkEuSx
```

This string is the decoded token. Although it didn't work for the flag13 user, it was accepted when used to log in as the level14 user.

---

And there you have it, the token is `2A31L79asukciNyi8uppkEuSx`.