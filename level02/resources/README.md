## Step 1: Identifying the User

We begin by checking our current user informations:

```bash
$ id
uid=2002(level02) gid=2002(level02) groups=2002(level02),100(users)
```

This shows that we are operating as the user `level02`.

---

## Step 2: Searching for Files

Next, let's check what files are in our `/home` directory:

```bash
$ ls
level02.pcap

$ file level02.pcap
level02.pcap: tcpdump capture file (little-endian) - version 2.4 (Ethernet, capture length 16777216)
```

We find a file named `level02.pcap`. Let's transfer it to our local machine for analysis:

```bash
$ scp -P 4242 level02@machine_ip:/home/level02/level02.pcap .
```

---

## Step 3: Analyzing the TCP Dump with Wireshark

Upon analyzing the packet capture file in Wireshark, we notice a packet where a password is requested. Following this packet, we see our machine responding with a series of packets, each containing a character.

When we concatenate these characters, we get the following string:

```
ft_wandr 7f 7f 7f NDRel 7f L0L 0d
```

We know from the ASCII table that `0x7f` corresponds to the delete character, and `0x0d` corresponds to the enter key. After processing this string to remove the deletions, we end up with:

```
ft_waNDReL0L
```

---

## Step 4: Obtaining the Flag

Finally, we switch to the `flag02` user and retrieve the flag:

```bash
$ su flag02
Password:
ft_waNDReL0L

$ getflag
Check flag.Here is your token: kooda2puivaav1idi4f57q8iq
```

---

And there you have it, the token is `kooda2puivaav1idi4f57q8iq`.
