## Step 1: Identifying the User

We begin by checking our current user informations:

```bash
$ id
uid=2000(level00) gid=2000(level00) groups=2000(level00),100(users)
```

This shows that we are operating as the user `level00`.

---

## Step 2: Searching for Files

Next, we attempt to find any files owned by the user `level00` or `flag00` :

```bash
$ find / -user flag00 -group flag00 2> /dev/null
/usr/sbin/john
/rofs/usr/sbin/john
```

We found two files: `/usr/sbin/john` and `/rofs/usr/sbin/john`. Let's check their contents:

```bash
$ cat /usr/sbin/john
cdiiddwpgswtgt

$ cat /rofs/usr/sbin/john
cdiiddwpgswtgt
```

Both files contain the string `cdiiddwpgswtgt`.

---

## Step 3: Decoding the String

The password doesn't work directly for the user `flag00`. Using the "Cipher Identifier" on [dcode.fr](https://www.dcode.fr), we identify that the string might be encrypted with a ROT algorithm.

After checking, the string is indeed encrypted with ROT11:

```bash
cdiiddwpgswtgt -> nottoohardhere
```

---

## Step 4: Obtaining the Flag

Finally, we switch to the `flag00` user and retrieve the flag:

```bash
$ su flag00
Password:
nottoohardhere

$ getflag
Check flag.Here is your token : f2av5il02puano7naaf6adaaf
```

---

And there you have it, the token is `f2av5il02puano7naaf6adaaf`.
