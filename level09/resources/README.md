## Step 1: Identifying the User

We begin by checking our current user informations:

```bash
$ id
uid=2009(level09) gid=2009(level09) groups=2009(level09),100(users)
```

This shows that we are operating as the user `level09`.

---
## Step 2: Searching for Files

```bash
$ ls -la
-rwsr-sr-x 1 flag09  level09 7640 Mar  5  2016 level09
----r--r-- 1 flag09  level09   26 Mar  5  2016 token


$ file level09
level09: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x0e1c5a0dfb537112250e1c78d5afec3104abb143, not stripped

$ file token
token: data

$ cat token
f4kmm6p|=pnDBDu


$ ./level09
You need to provied only one arg.

$ ./level09 token
tpmhr
```
The level09 binary is a setuid ELF executable, meaning it executes with flag09 user's privileges.

The program produces the output tpmhr. It appears that the level09 binary encrypts the provided string and then prints the encrypted version.
By comparing the input (token) with the output, we deduce that the program uses a basic encryption algorithm, likely involving character shifts.

```bash
$ ./level09 token
tpmhr

t o k e n
+ + + + +
0 1 2 3 4
= = = = =
t p m h r
```

---
## Step 3: Reversing the Encryption Algorithm
```bash
$ xxd token
0000000: 6634 6b6d 6d36 707c 3d82 7f70 826e 8382  f4kmm6p|=..p.n..
0000010: 4442 8344 757b 7f8c 890a                 DB.Du{....

--->

0x66 0x34  0x6b 0x6d  0x6d 0x36  0x70 0x7c  0x3d 0x82  0x7f 0x70  0x82 0x6e  0x83 0x82
0x44 0x42  0x83 0x44  0x75 0x7b  0x7f 0x8c  0x89 0x0a
```

Next, we interpret the hexadecimal values and reverse the algorithm, which seems to be subtracting the position of each character in the string from its ASCII value.
```
0x66 - 0  = 'f'
0x34 - 1  = '3'
0x6b - 2  = 'i'
0x6d - 3  = 'j'
0x6d - 4  = 'i'
0x36 - 5  = '1'
0x70 - 6  = 'j'
0x7c - 7  = 'u'
0x3d - 8  = '5'
0x82 - 9  = 'y'
0x7f - 10 = 'u'
0x70 - 11 = 'e'
0x82 - 12 = 'v'
0x6e - 13 = 'a'
0x83 - 14 = 'u'
0x82 - 15 = 's'
0x44 - 16 = '4'
0x42 - 17 = '1'
0x83 - 18 = 'q'
0x44 - 19 = '1'
0x75 - 20 = 'a'
0x7b - 21 = 'f'
0x7f - 22 = 'i'
0x8c - 23 = 'u'
0x89 - 24 = 'q'
```

Reversing the encryption, we get the original string:
```
f3iji1ju5yuevaus41q1afiuq
```

```bash
$ su flag09
Password : 
f3iji1ju5yuevaus41q1afiuq

% getflag
Check flag.Here is your token : s5cAJpM8ev6XHw998pRWG728z
```
---

And there you have it, the token is `s5cAJpM8ev6XHw998pRWG728z`.
